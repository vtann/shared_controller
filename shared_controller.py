import os
import logging
import base64
import json
import ast
import urllib2
from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication

LOG = logging.getLogger('ryu.app.shared_controller')

# supported ofctl versions in this restful app
supported_ofctl = {
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3
}

#Ryu IP and port
ryu_IP = 'localhost'
ryu_port = 8080

#load config file
config = os.getenv('SharedControllerAppConfig')
with open(config) as tenants_json:
    tenants_data = json.load(tenants_json)


class Tenant(object):
    def __init__(self,name,**kwargs):
        self.name = name
        self.tables = []
        for k,v in kwargs.iteritems():
            setattr(self,k,v)
        for i in xrange(self.nof_table):
            self.tables.append(i + self.offset_table)
        #User userid and password to generate authtoken
        self.authtoken = 'Basic ' + base64.b64encode(self.authkey)

    def xlat_switch_to_tenant(self, flow):
        flow['table_id'] -= self.offset_table
        for action in flow['actions']:
            if action.find('GOTO_TABLE:') == -1:
                continue
            index = flow['actions'].index(action)
            action = action.replace('GOTO_TABLE:','')
            action = int(action)
            action -= self.offset_table
            action = str(action)
            flow['actions'][index] = 'GOTO_TABLE:'+ action
        return flow

    def xlat_tenant_to_switch(self,flow):
        #in the api to modify flow: if table_id is missing ~ table_id = 0 (default value)
        if 'table_id' not in flow:
            flow['table_id'] = self.tables[0]
        else:
            #table_id exists. Translate table_id
            flow['table_id'] += self.offset_table

        #validate table_id
        if flow['table_id'] not in self.tables:
            return None #Not acceptable. Table id is out of range

        #validate dl_vlan
        if 'match' in flow:
            if 'dl_vlan' in flow['match']:
                if flow['match']['dl_vlan'] not in self.vlans:
                    return None #Not acceptable. Vlan is out of range

        #validate if actions not existing. This is for get flows stats filtered by field.
        if 'actions' not in flow:
            return flow

        #validate if actions is empty. Actions = drop (actions = [])
        if len(flow['actions']) == 0:
            return flow

        for action in flow['actions']:
            #Block PUSH_VLAN and POP_VLAN action
            if action['type'] in ['PUSH_VLAN','POP_VLAN']:
                return None
            #validate if vlan_id is in defined range
            if ('field' and 'value') in action:
                if (action['field'] == 'vlan_vid') and ((action['value'] - 4096) not in self.vlans):
                    return None
            #translate table_id existing in actions
            if 'table_id' not in action:
                continue
            index = flow['actions'].index(action) #Table_id exists in actions
            flow['actions'][index]['table_id'] += self.offset_table
            if flow['actions'][index]['table_id'] not in self.tables:
                return None #Not accepcted. Table id is out of range
        return flow

#create global objects of tenants
tenant_list = []
tenant_by_auth = {}
tenant_by_name = {}
for name, data in tenants_data.iteritems():
    t = Tenant(name, **data)
    tenant_list.append(t)
    tenant_by_auth[t.authtoken] = t
    tenant_by_name[t.name] = t

def query_ryu(url,data):
    list_flows = []
    for single_data in data:
        req_to_ryu = urllib2.Request(url, single_data, {'Content-Type': 'application/json'})
        #error
        try:
            res_from_ryu = urllib2.urlopen(req_to_ryu)
        except urllib2.HTTPError, err:
            return err.code
        response = res_from_ryu.read()
        if len(response) == 0:
            continue
        flows = json.loads(response)
        list_flows.append(flows)
    return list_flows

#translate a bundle of flows (a list of dictionaries of single flow)
def xlat_flows_from_ryu(return_flows,dpid,tenant):
    xlat_flows = {dpid:[]}
    for single_dict in return_flows:
        for single_flow in single_dict[dpid]:
            xlat_flow =  tenant.xlat_switch_to_tenant(single_flow)
            xlat_flows[dpid].append(xlat_flow)
    return xlat_flows

class StatsController2(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(StatsController2, self).__init__(req, link, data, **config)
        self.waiters = data['waiters']


    #Get all dpids
    def get_dpids(self, req, **_kwargs):
        url = 'http://{}:{}/stats/switches'.format(ryu_IP, ryu_port)
        req_to_ryu = urllib2.Request(url)
        res_from_ryu = urllib2.urlopen(req_to_ryu)
        body_to_tenant = res_from_ryu.read()
        return Response(content_type='application/json', body=body_to_tenant) #Response the list of dpids to tenant

    #Get flows stats
    def get_flow_stats(self, req, dpid, **_kwargs):

        if req.body == '':
            flow = {}

        else:
            try:
                flow = ast.literal_eval(req.body)

            except SyntaxError:
                LOG.debug('invalid syntax %s', req.body)
                return Response(status=400)

        #url of Ryu ofctl_rest API
        url = 'http://{}:{}/stats/flow/{}'.format(ryu_IP, ryu_port, dpid)

        #Get the header 'Authorization' from request of tenant
        header_auth = req.headers['Authorization']
        if header_auth not in tenant_by_auth:
            return Response(status=403) #Forbidden

        tenant = tenant_by_auth[header_auth] #authorized tenant

        #Get all flows stats API (GET method)
        if (req.method == 'GET'):
            data_list_ryu = []
            for tableid in tenant.tables:
                data_list_ryu.append(json.dumps({"table_id": tableid}))
            return_flows = query_ryu(url,data_list_ryu)
            if type(return_flows) is not list:
               return Response(status=return_flows) #return the error code
            xlat_flows = xlat_flows_from_ryu(return_flows,dpid,tenant)
            body_to_tenant = json.dumps(xlat_flows)
            return Response(content_type='application/json', body=body_to_tenant) #Response the list of flows to tenant

        #Get flows stats filtered by fields API (POST method)
        elif req.method == 'POST':
            if (len(flow) == 0) or ('table_id' not in flow) or (flow['table_id'] == 0xff):
                data_list_ryu = []
                for tableid in tenant.tables:
                    flow['table_id'] = tableid
                    data_req_to_ryu = json.dumps(flow)
                    data_list_ryu.append(data_req_to_ryu)
                return_flows = query_ryu(url,data_list_ryu)
                if type(return_flows) is not list:
                    return Response(status=return_flows) #return the error code
                xlat_flows = xlat_flows_from_ryu(return_flows,dpid,tenant)
                body_to_tenant = json.dumps(xlat_flows)
                return Response(content_type='application/json', body=body_to_tenant) #Response the list of flows to tenant

            #specific table_id
            xlat_flow = tenant.xlat_tenant_to_switch(flow)
            if xlat_flow == None:
                return Response(status = 406) #not acceptable
            data_to_ryu = json.dumps(xlat_flow)
            return_flows = query_ryu(url,(data_to_ryu,))
            if type(return_flows) is not list:
                return Response(status=return_flows) #return error code
            xlat_flows = xlat_flows_from_ryu(return_flows,dpid,tenant)
            body_to_tenant = json.dumps(xlat_flows)
            return Response(content_type='application/json', body=body_to_tenant)

    #Modify flow entry (add/delete/modify)
    def mod_flow_entry(self, req, cmd, **_kwargs):

        try:
            flow = ast.literal_eval(req.body)

        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        header_auth = req.headers['Authorization']
        if header_auth not in tenant_by_auth:
            return Response(status=403) #Forbidden. Invalid tenant

        tenant = tenant_by_auth[header_auth] #authorized tenant
        xlat_flow = tenant.xlat_tenant_to_switch(flow)

        if xlat_flow == None:
            return Response(status=406) #Not acceptable

        url = 'http://{}:{}/stats/flowentry/{}'.format(ryu_IP, ryu_port, cmd)
        data_to_ryu = json.dumps(xlat_flow)
        req_to_ryu = urllib2.Request(url, data_to_ryu, {'Content-Type': 'application/json'})
        try:
            res_from_ryu = urllib2.urlopen(req_to_ryu)
            return Response(status=res_from_ryu.code) #expectation: code = 200
        except urllib2.HTTPError, err:
            return Response(status=err.code)

    #Delete all flows
    def delete_flow_entry(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

	url = 'http://{}:{}/stats/flowentry/delete'.format(ryu_IP, ryu_port)
        header_auth = req.headers['Authorization']
        if header_auth not in tenant_by_auth:
            return Response(status=403) #Forbidden. Invalid tenant

        tenant = tenant_by_auth[header_auth] #authorized tenant
        data_list_ryu = []
        for tableid in tenant.tables:
            data_to_ryu = json.dumps({"dpid": dpid, "table_id": tableid})
            data_list_ryu.append(data_to_ryu)
        response = query_ryu(url,data_list_ryu)
        if type(response) is not list:
            return Response(status=response) #return error code
        return Response(status=200) #successful delete all flows of tenant

class RestStatsApi2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(RestStatsApi2, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper
        wsgi.registory['StatsController2'] = self.data

        path = '/sharedcontroller/stats'
        uri = path + '/switches'
        mapper.connect('stats', uri,
                       controller=StatsController2, action='get_dpids',
                       conditions=dict(method=['GET']))

        uri = path + '/flow/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController2, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/flowentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController2, action='mod_flow_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/flowentry/clear/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController2, action='delete_flow_entry',
                       conditions=dict(method=['DELETE']))

    #wait for switches connect to controller before sending pre-provisioned flows
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def pre_provision(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofctl = supported_ofctl.get(dp.ofproto.OFP_VERSION)

        url = 'http://{}:{}/stats/switches'.format(ryu_IP, ryu_port)
        req1 = urllib2.Request(url)
        response = urllib2.urlopen(req1)
        dp_list = response.read()
        dpid_list = json.loads(dp_list)

        #add pre-provisioned flows to switches
        url = 'http://{}:{}/stats/flowentry/add'.format(ryu_IP, ryu_port)
        for dpid_pre in dpid_list:
            for index in xrange(len(tenant_list)):
                for vlanid in xrange(len(tenant_list[index].vlans)):
                    data_pre = json.dumps({"dpid": dpid_pre, "priority": 0, "match": {"dl_vlan":hex(tenant_list[index].vlans[vlanid]| 0x1000)}, "actions": [{"type":"GOTO_TABLE","table_id": tenant_list[index].offset_table}]})
                    req_pre = urllib2.Request(url, data_pre, {'Content-Type': 'application/json'})
                    response_pre = urllib2.urlopen(req_pre)
