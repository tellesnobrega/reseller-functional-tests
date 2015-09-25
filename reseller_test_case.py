from keystoneclient.auth.identity import v3
from keystoneclient import session
from keystoneclient.v3 import client as keystoneclient
from subprocess import call, Popen, PIPE
import json
import requests
import traceback

# Check these variables:
keystone_url = 'http://127.0.0.1:35357/v3'
admin_role = '0adb12ef83dc450a89d2d0f7fc1e3bc2'
member_role = 'a232acb7da5b4ead924d5d7f8d3c4f44'
admin_password = 'nomoresecrete'

project_url = keystone_url + "/projects"
default_token_json = '{ "auth": { "identity": { "methods": [ "password" ], "password": { "user": { "domain": { "name": "Default" }, "name": "admin", "password": "' + admin_password + '" } } }, "scope": { "project": { "domain": { "name": "Default" }, "name": "demo" } } } }'
a_token_json = ' { "auth": { "identity": { "methods": [ "password" ], "password": { "user": { "id": "%s", "password": "secretsecret" } } }, "scope": { "project": { "name": "Project_A" } } } }'
b_token_json = ' { "auth": { "identity": { "methods": [ "password" ], "password": { "user": { "id": "%s", "password": "secretsecret" } } }, "scope": { "project": { "domain": { "name": "Project_A" }, "name": "Project_B" } } } }'
sub_b_token_json = ' { "auth": { "identity": { "methods": [ "password" ], "password": { "user": { "id": "%s", "password": "secretsecret" } } }, "scope": { "project": { "domain": { "name": "Project_B" }, "name": "%s" } } } }'
sub_a_token_json = ' { "auth": { "identity": { "methods": [ "password" ], "password": { "user": { "id": "%s", "password": "secretsecret" } } }, "scope": { "project": { "domain": { "name": "Project_A" }, "name": "%s" } } } }'

def project_json(name, is_domain, parent_id):
    return '{ "project": { "description": "My new project", "parent_id": "%s", "enabled": true, "name": "%s", "is_domain": %s } }' % (parent_id, name, is_domain) if parent_id else '{ "project": { "description": "My new project", "enabled": true, "name": "%s", "is_domain": %s } }' % (name, is_domain) 


def get_token(token_json):
    token_headers = {'Content-Type': 'application/json'}

    r = requests.post(keystone_url + "/auth/tokens",
                      headers=token_headers,
                      data=token_json)
    try:
        return r.headers['x-subject-token']
    except:
        return r._content

def get_projects(token):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    r = requests.get(project_url,
                     headers=headers)

    return r._content

def create_project(data, token):
    create_project_headers = {'X-Auth-Token': token,
                              'Content-Type': 'application/json'}

    r = requests.post(project_url,
                      headers=create_project_headers,
                      data=data)

    try:
        return json.loads(r._content)['project']['id']
    except:
        return r._content


def update_project(token, project_id, data):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    r = requests.patch(project_url+ "/%s" % project_id,
                       headers=headers,
                       data=data)

    return r._content

def enable_project(token, project_id):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    data = '{ "project": {"enabled": true}}'

    r = requests.patch(project_url+ "/%s" % project_id,
                       headers=headers,
                       data=data)
    print "Enabled project %s" % project_id

def disable_project(token, project_id):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    data = '{ "project": {"enabled": false}}'

    r = requests.patch(project_url+ "/%s" % project_id,
                       headers=headers,
                       data=data) 
    print "Disabled project %s" % project_id


def delete_project(token, project_id):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    r = requests.delete(project_url+ "/%s" % project_id,
                        headers=headers) 
    print "Deleted project %s" % project_id
    return r._content

def create_user(token, domain_id, name):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    data = '{ "user": {"description": "User", "domain_id": "%s", "email": "jdoe@example.com", "enabled": true, "name": "%s", "password": "secretsecret" } }' % (domain_id, name)

    r = requests.post(keystone_url + '/users',
                      headers=headers,
                      data=data)


    user_id = json.loads(r._content)['user']['id']
    print "Created user %s in project %s" % (user_id, domain_id)
    return json.loads(r._content)['user']['id']

def grant_user_role(token, user_id, role, projects):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    for project in projects:
        grant_role = requests.put(project_url + "/%s/users/%s/roles/%s" % (project, user_id, role),
                                 headers=headers)
        print "Granted role for user %s in project %s" % (user_id, project)

def grant_user_inherited_role(token, user_id, role, projects):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    for project in projects:
        grant_role = requests.put(keystone_url + "/OS-INHERIT/projects/%s/users/%s/roles/%s/inherited_to_projects" % (project, user_id, role),
                                 headers=headers)
        print "Granted inherited role for user %s in project %s" % (user_id, project)

def get_subtree(token, project_id):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    r = requests.get(project_url + "/%s?subtree_as_ids" % project_id,
                     headers=headers)

    return r._content

def get_parents(token, project_id):
    headers = {'X-Auth-Token': token,
               'Content-Type': 'application/json'}

    r = requests.get(project_url + "/%s?parents_as_ids" % project_id,
                     headers=headers)

    return r._content

def dict_to_list(item, final_list):
    if isinstance(item, dict):
        for key in item:
            final_list.append(key)
            dict_to_list(item[key], final_list)
    return None

def tear_down(token, projects):
    for project_id in projects:
        if project_id:
            disable_project(token, project_id)
            delete_project(token, project_id)

def main():
    try:
        # Initializing id variables
        f_project_id = e_project_id = d_project_id = c_project_id = b_project_id = a_project_id = None
        default_token = get_token(default_token_json)
        # projects_id = create_hierarchy(token)
        # Create Project A
        raw_input("Creating and configuring hierarchy. Press ENTER to continue...")
        a_project_json = project_json('Project_A', 'true', None)
        a_project_id = create_project(a_project_json, default_token)
        print "Project A: %s" % a_project_id
        admin_a = create_user(default_token, a_project_id, 'admin_a')
        member_a = create_user(default_token, a_project_id, 'member_a')
        grant_user_role(default_token, admin_a, admin_role, [a_project_id])
        grant_user_role(default_token, member_a, member_role, [a_project_id])
        admin_a_token = get_token(a_token_json % admin_a)
        print "Created a token"

        # Create Project B
        b_project_json = project_json('Project_B', 'true', a_project_id)
        print "Created b Json"
        b_project_id = create_project(b_project_json, admin_a_token)
        print "Project B: %s" % b_project_id
        admin_b = create_user(admin_a_token, b_project_id, 'admin_b')
        member_b = create_user(admin_a_token, b_project_id, 'member_b')
        grant_user_role(admin_a_token, admin_b, admin_role, [b_project_id])
        grant_user_role(admin_a_token, member_b, member_role, [b_project_id])
        admin_b_token = get_token(b_token_json % admin_b)

        # Create Project C
        c_project_json = project_json('Project_C', 'false', a_project_id)
        c_project_id = create_project(c_project_json, admin_a_token)
        print "Project C: %s" % c_project_id

        # Create Project D
        d_project_json = project_json('Project_D', 'false', b_project_id)
        d_project_id = create_project(d_project_json, admin_b_token)
        print "Project D: %s" % d_project_id

        # Create Project E
        e_project_json = project_json('Project_E', 'false', b_project_id)
        e_project_id = create_project(e_project_json, admin_b_token)
        print "Project E: %s" % e_project_id

        # Create Project F
        f_project_json = project_json('Project_F', 'false', c_project_id)
        f_project_id = create_project(f_project_json, admin_a_token)
        print "Project F: %s" % f_project_id
        raw_input("Projects configured...")

        raw_input("Granting user A roles on projects C and F...")
        # Granting user A role for projects C and F
        grant_user_role(default_token, admin_a, admin_role, [c_project_id, f_project_id])
        grant_user_role(default_token, member_a, member_role, [c_project_id, f_project_id])
        raw_input("Granting user B roles on projects D and E...")
        # Granting user B role for projects D and E
        grant_user_role(admin_a_token, admin_b, admin_role, [d_project_id, e_project_id])
        grant_user_role(admin_a_token, member_b, member_role, [d_project_id, e_project_id])

        # User authenticated in A list subtree - expected B,C,F
        a_subtree = json.loads(get_subtree(admin_a_token, a_project_id))['project']['subtree']

        subtree_as_list = []
        dict_to_list(a_subtree, subtree_as_list)
        raw_input("Testing A admin listing subtree...")

        if (b_project_id not in subtree_as_list or c_project_id not in subtree_as_list or 
                f_project_id not in subtree_as_list or len(subtree_as_list) != 3):
            raise Exception('Subtree A is not as expected')
        else:
            print subtree_as_list
            raw_input("A's Subtree is ok...")

        # User authenticated in B list subtree - expected D, E
        b_subtree = json.loads(get_subtree(admin_b_token, b_project_id))['project']['subtree']
        subtree_as_list = []
        dict_to_list(b_subtree, subtree_as_list)
        raw_input("Testing B admin listing subtree...")
        if (d_project_id not in subtree_as_list or e_project_id not in subtree_as_list or len(subtree_as_list) != 2):
            raise Exception('Subtree B is not as expected')
        else:
            print subtree_as_list
            raw_input("B's Subtree is ok...")

        # User authenticated in D list parents - expected B
        raw_input("Testing D admin listing parents...")
        admin_d_token = get_token(sub_b_token_json % (admin_b, 'Project_D'))
        d_parents = json.loads(get_parents(admin_d_token, d_project_id))
        parents_as_list = []
        dict_to_list(d_parents, parents_as_list)

        if (b_project_id not in parents_as_list) and (len(parents_as_list) != 1):
            tear_down(default_token, [f_project_id, e_project_id, d_project_id, c_project_id, b_project_id, a_project_id])
            raise Exception('Parents D is not as expected')
        else:
            print [b_project_id]
            raw_input("D's Parents is ok...")

        # User authenticated in F list parents - expected C,A
        f_token = get_token(sub_a_token_json % (admin_a, 'Project_F'))
        f_parents = json.loads(get_parents(f_token, f_project_id))['project']['parents']
        parents_as_list = []
        dict_to_list(f_parents, parents_as_list)

        if (a_project_id not in parents_as_list or c_project_id not in parents_as_list or len(parents_as_list) != 2):
            raise Exception('Parents F is not as expected')

        # Member User authenticated in A list subtree - expected 403
        member_a_token = get_token(a_token_json % member_a)
        a_subtree = json.loads(get_subtree(member_a_token, a_project_id))['error']['code']
        if a_subtree != 403:
            raise Exception('Member user cannot list subtree')

        # Member User autenticated in C list parents - expected 403
        member_a_in_c_token = get_token(sub_a_token_json % (member_a, 'Project_C'))
        c_parents = json.loads(get_parents(member_a_in_c_token, c_project_id))['error']['code']
        if c_parents != 403:
            raise Exception('Member user cannot list subtree')

        g_project_json = project_json('Project_G', 'false', a_project_id)
        g_project = json.loads(create_project(g_project_json, member_a_token))['error']['code']
        if g_project != 403:
            raise Exception('Member user cannot project in A')

        # Admin user delete enabled project A
        delete_enabled = json.loads(delete_project(admin_a_token, a_project_id))['error']['code']
        if delete_enabled != 403:
            raise Exception('Cannot delete an enabled project')

        # Admin user delete C when F still exists - expected 403
        disable_project(admin_a_token, f_project_id)
        disable_project(admin_a_token, c_project_id)
        delete_child_exists = json.loads(delete_project(admin_a_token, c_project_id))['error']['code']
        if delete_child_exists != 403:
            raise Exception('Cannot delete a project that has a child') 
        enable_project(admin_a_token, c_project_id)
        enable_project(admin_a_token, f_project_id)

        # Admin user update parent - expected 403
        data = '{ "project": {"parent_id": "%s"}}' % e_project_id
        update_parent = json.loads(update_project(admin_b_token, d_project_id, data))['error']['code']
        if update_parent != 403:
            raise Exception('Cannot update projects parent')

        # Admin user update domain_id
        data = '{ "project": {"domain_id": "%s"}}' % a_project_id
        update_domain = json.loads(update_project(admin_d_token, d_project_id, data))['error']['code']
        if update_domain != 400:
            raise Exception('Cannot update projects domain')

        # Admin user cannot create a project that acts as a domain with the same name of an existing project that acts as a domain - expected 409
        create_is_domain_project_fails = json.loads(create_project(b_project_json, admin_a_token))['error']['code']
        if create_is_domain_project_fails != 409:
            raise Exception('Cannot create project that acts as a domain with the same name of an existing project that acts as a domain') 

        # Admin user cannot create a project with the same name of an existing project in the same domain
        create_project_fails = json.loads(create_project(c_project_json, admin_a_token))['error']['code']
        if create_project_fails != 409:
            raise Exception('Cannot create project with the same name of an existing project in the same domain') 

        # # # Test creation/list of user/assignments and inherited assignments # # #
        raw_input("Testing inherited role assignemnts...")
        admin_a_aux = create_user(default_token, a_project_id, 'admin_a_aux')
        member_a_aux = create_user(default_token, a_project_id, 'member_a_aux')
        member_b_aux = create_user(default_token, b_project_id, 'member_b_aux')
        grant_user_role(default_token, admin_a_aux, admin_role, [a_project_id])
        grant_user_inherited_role(default_token, member_a_aux, member_role, [a_project_id])
        grant_user_inherited_role(default_token, member_b_aux, member_role, [b_project_id])
        admin_a_aux_token = get_token(a_token_json % admin_a_aux)
        raw_input("Granting inherited role assignment in Project A...")
        if not admin_a_aux_token:
            raise Exception('Authentication failed for user in Project A')

        admin_a_in_b_token = json.loads(get_token(b_token_json % admin_a_aux))['error']['code']
        if admin_a_in_b_token != 401:
            raise Exception('User A cannot authenticate in Project B')
        admin_a_in_c_token = json.loads(get_token(sub_a_token_json % (admin_a_aux, 'Project_C')))['error']['code']
        if admin_a_in_c_token != 401:
            raise Exception('User A cannot authenticate in Project C')
        admin_a_in_f_token = json.loads(get_token(sub_a_token_json % (admin_a_aux, 'Project_F')))['error']['code']
        if admin_a_in_f_token != 401:
            raise Exception('User A cannot authenticate in Project F')

        member_a_in_b_token = json.loads(get_token(b_token_json % member_a_aux))['error']['code']
        member_a_in_d_token = json.loads(get_token(sub_b_token_json % (member_a_aux, 'Project_D')))['error']['code']
        member_a_in_e_token = json.loads(get_token(sub_b_token_json % (member_a_aux, 'Project_E')))['error']['code']
        member_a_in_c_token = get_token(sub_a_token_json % (member_a_aux, 'Project_C'))
        member_a_in_f_token = get_token(sub_a_token_json % (member_a_aux, 'Project_F'))
        if member_a_in_b_token != 401:
            raise Exception('User A_aux should be able to authenticate in B due to inherited role')
        raw_input('User could not be authenticated in project B...')

        if member_a_in_d_token != 401:
            raise Exception('User A_aux should be able to authenticate in D due to inherited role')
        raw_input('User could not be authenticated in project D...')
        if member_a_in_e_token != 401:
            raise Exception('User A_aux should be able to authenticate in B due to inherited role')
        raw_input('User could not be authenticated in project E...')
        if not member_a_in_c_token:
            raise Exception('User A_aux should be able to authenticate in C due to inherited role')
        if not member_a_in_f_token:
            raise Exception('User A_aux should be able to authenticate in F due to inherited role')
        raw_input('User A succesfully authenticated in projects C and F...')

        member_b_in_d_token = get_token(sub_b_token_json % (member_a_aux, 'Project_D'))
        member_b_in_e_token = get_token(sub_b_token_json % (member_a_aux, 'Project_E'))
        if not member_b_in_d_token:
            raise Exception('User B_aux should be able to authenticate in D due to inherited role')
        if not member_a_in_e_token:
            raise Exception('User B_aux should be able to authenticate in E due to inherited role')

        # Admin user delete project B (domain) when projects are enabled - expected 403
        disable_project(admin_a_token, b_project_id)
        delete_project_is_domain_childs_enabled = delete_project(admin_a_token, b_project_id)
        if delete_project_is_domain_childs_enabled:
            raise Exception('User should be able to delete a domain even with projects enabled') 

        raw_input("Tests succesful. Tearing down now")

        tear_down(default_token, [f_project_id, e_project_id, d_project_id, c_project_id, b_project_id, a_project_id])

    except Exception as e:
        print "<<<<<Error>>>>>>"
        print e
        print(traceback.format_exc())
        print "<<<<<Error>>>>>>"
        tear_down(default_token, [f_project_id, e_project_id, d_project_id, c_project_id, b_project_id, a_project_id])

if __name__ == "__main__":
     main()
