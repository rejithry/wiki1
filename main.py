
import webapp2
from google.appengine.ext import db
import cgi
import logging
import re
import hmac, hashlib
import HTMLParser

edit_link_page = """ <html>

<head>

  <style type="text/css">
.top_right {
    position:absolute;
    top: 0;
    right:0;
    padding:3px;
    font-family:"Verdana",Times,serif;
    font-family:Arial,Helvetica,sans-serif;
}
  </style>
</head>
    <body>
      <p class="top_right">
      <a href = "%(edit_link)s"   > %(edit_link_text)s </a>&nbsp;&nbsp;
      <a href = "%(hist_link)s"   > %(hist_link_text)s </a>&nbsp;&nbsp;
      <a href = "%(login_link)s"  > %(login_link_text)s </a></br>
      <a href = "/signup"  > signup </a>
      
    </p>
    </body>
    </html>
"""

home_page = """ <html>


    <br><br><br><br>
    <form method = post>
    <label>
    <textarea name = "content" rows=40 cols=120>%(content)s</textarea>
    </label>
    <div></div>

    <input type = submit value = submit name = submit />

    </form> """
home_page_non_edit = """ <html>
    <body>
    <br><br><br><br>
    <form method = post>
    <label>
    <textarea readonly = True name = "content" rows=40 cols=120>%(content)s</textarea>
    </label>
    <div></div>
    </form> """
signup_page = """
<html>
<head>



    
    </head>
    <body>
    
    <div class="container">
<form method = post>

  <table>
    <tr>
      <td align="right">User Name</td>
      <td align="left"><input type = text name = "username" value= "%(user_name)s" /></td>
    </tr>
    <tr>
      <td align="right">Password</td>
      <td align="left"><input name = "password" type = password value = "%(password_1)s" /></td>
    </tr>
    <tr>
      <td align="right">Retype password</td>
      <td align="left"><input name = "verify" type = password  value = "%(password_2)s" /></td>
    </tr>
    <tr>
      <td align="right">Email(optional):</td>
      <td align="left"><input name = "email" type = text value = "%(email)s" /></td>
    </tr>
  </table>

    <div style "color : red" >%(error)s</div>
    <div></div>
    <input type = submit value = submit name = submit />
    </form> 
    """        

login_page = """
<head>

  <style type="text/css">
.top_right {
    position:absolute;
    top: 0;
    right:0;
    padding:3px;
    font-family:"Verdana",Times,serif;
    font-family:Arial,Helvetica,sans-serif;
}
  </style>
</head>


      <p class="top_right">
      <a href = "/signup"  > signup </a>
      
    </p>
   
    
<form method = post>

  <table>
    <tr>
      <td align="right">User Name</td>
      <td align="left"><input type = text name = "username" value= "%(user_name)s" /></td>
    </tr>
    <tr>
      <td align="right">Password</td>
      <td align="left"><input name = "password" type = password value = "%(password)s" /></td>
    </tr>
    </table>
   <div style "color : red" >%(error)s</div>
    <input type = submit value = submit name = submit />
    </form> """ 
    
               
secret = 'fart'
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
class WikHandler(webapp2.RequestHandler):

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, str(cookie_val)))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_name', user.user_name)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_name=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_name = self.read_secure_cookie('user_name')
        self.user = user_name and User.by_name(user_name)   
              
class Wiki(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_title(cls, title):
        w = Wiki.all().filter('title =',title).get()
        return w

class WikiHist(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add = True)


    @classmethod
    def by_title(cls, title):
        w = Wiki.all().filter('title =',title).get()
        return w
        
class User(db.Model):
    user_name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True) 
    
    @classmethod
    def login(cls, user_name, password):
        u = User.by_name(user_name)
        if u and u.password == password:
            return u
    @classmethod
    def by_name(cls, user_name):
        u = User.all().filter('user_name =',user_name).get()
        return u

class WikiPageHandler(WikHandler):
    def write_form(self,  content=''):
        self.response.out.write(home_page % {'content' : content })
        
    def write_form_non_edit(self, title='', content=''):
        self.response.out.write(home_page_non_edit % {'title': title, 'content' : content })
        
    def write_form_edit_link(self, edit_link, edit_link_text,  login_link, login_link_text , hist_link, hist_link_text):
        self.response.out.write(edit_link_page % {'edit_link' : edit_link, 'login_link' : login_link,  'edit_link_text' : edit_link_text, 'login_link_text': login_link_text, 'hist_link': hist_link, 'hist_link_text' : hist_link_text })

 
    def get(self):
        path = self.request.path[1:]
        if path == 'index_page_of_wiki':
        	if self.request.query_string:
        		self.redirect('/?' + self.request.query_string)
        	else:
        		self.redirect('/')
#		if self.request.query_string:
#            		w = WikiHist.get_by_id(int(self.request.query_string.split('=')[1]))
#            		self.response.out.write(HTMLParser.HTMLParser().unescape(w.content))
#            	else:
        		
        if not path:
            if self.request.query_string:
            	w = WikiHist.get_by_id(int(self.request.query_string.split('=')[1]))
            	self.response.out.write(HTMLParser.HTMLParser().unescape(w.content))
            else:
		    w = Wiki.by_title('index_page_of_wiki')
		    if not w:
			content = cgi.escape("<h1> Welcome to Wiki </h1>", True)
			wiki = Wiki(title='index_page_of_wiki', content=content,key_name='index_page_of_wiki')
			wiki.put()
			w = Wiki.by_title('index_page_of_wiki')
			wikiHist = WikiHist(title='index_page_of_wiki', content=content)
			wikiHist.put()
		    if self.user:
			self.write_form_edit_link('http://' + self.request.url.split('/')[2] + '/_edit/index_page_of_wiki', 'edit','/logout','logout(' + self.user.user_name + ')', 'http://' + self.request.url.split('/')[2] + '/_history/index_page_of_wiki' , 'hist')
		    else:
			self.write_form_edit_link('http://' + self.request.url.split('/')[2] + '/_edit/index_page_of_wiki', '','/login','login',  'http://' + self.request.url.split('/')[2] + '/_history/index_page_of_wiki' , 'hist')
		    if  self.request.query_string:
			w = WikiHist.get_by_id(int(self.request.query_string.split('=')[1]))
		    self.response.out.write(HTMLParser.HTMLParser().unescape(w.content))
            	
        else:
        
            w = Wiki.by_title(path)
            if w:
                if self.user:
	        	self.write_form_edit_link('http://' + self.request.url.split('/')[2] + '/' + '_edit/' + path, 'edit','/logout?page=' + path,'logout(' + self.user.user_name + ')', 'http://' + self.request.url.split('/')[2] + '/_history/' + path , 'hist')
	        else:
            		self.write_form_edit_link('http://' + self.request.url.split('/')[2] + '/' + '_edit/' + path, '','/login','login', 'http://' + self.request.url.split('/')[2] + '/_history/' + path , 'hist')
		if  self.request.query_string:
			w = WikiHist.get_by_id(int(self.request.query_string.split('=')[1]))
                self.response.out.write(HTMLParser.HTMLParser().unescape(w.content))
            else:
                if self.user:
                    if path[:5] == '_edit':
                        w = Wiki.by_title(path.split('/')[1])
                        if w:
                            self.write_form_edit_link('http://' + self.request.url.split('/')[2] +  '/' + path.split('/')[1], 'view','/logout?page=' + path.split('/')[1],'logout(' + self.user.user_name + ')' , 'http://' + self.request.url.split('/')[2] + '/_history/' + path , '')
                            self.write_form(content=w.content)
                        else:
                            self.write_form_edit_link('http://' + self.request.url.split('/')[2] +  '/' + path.split('/')[1], '','/logout?page=' + path.split('/')[1],'logout(' + self.user.user_name + ')', 'http://' + self.request.url.split('/')[2] + '/_history/' + path, '')
                            self.write_form()
                    elif path[:8] == '_history':
		        html_string = """<table>"""
		        title = self.request.path[1:].split('/')[1]
		        q = db.GqlQuery("SELECT * FROM WikiHist WHERE title = :t", t=title)
		        for entry in q:
		            	html_string = html_string + "<tr><td>" + str(entry.created) + "</td><td>" + entry.content + "</td><td><a href = " +  "http://" + self.request.url.split('/')[2] +  '/' + path.split('/')[1] +  "?v=" + str(entry.key().id()) +">view</a>"  + "</td></tr>" 
		        html_string = html_string + """</tr></table>"""
		        self.response.out.write(html_string)
                    else:
                        self.redirect('/_edit/' + path)
                else:
	               	self.response.out.write("You need to login. Use the below form to login")
	                self.redirect('/login')
                
    def post(self):
        title = self.request.path[1:].split('/')[1]
        w = Wiki.by_title(title)
        content = cgi.escape(self.request.get('content'), True)
        if w:
            myKey = db.Key.from_path('Wiki', title)
            rec = db.get(myKey)
            rec.content = content
            rec.put()
            wikiHist = WikiHist(title=title, content=content)
            wikiHist.put()
        else:
            wiki = Wiki(title=title, content=content,key_name=title)
            wiki.put()
            wikiHist = WikiHist(title=title, content=content)
            wikiHist.put()
        self.redirect('/' + title)
        
class EditPageHandler(WikHandler):
    def write_form(self, title='', content=''):
        self.response.out.write(home_page_non_edit % {'title': title, 'content' : content })

    def get(self):
        if self.user:
            self.response.write(home_page)
        else:
            self.write_form()
    def post(self):
        title = self.request.get('title')
        content = cgi.escape(self.request.get('content'), True)
        wiki = Wiki(title=title, content=content)
        wiki.put()
        self.redirect('/')


class SignupHandler(WikHandler):
    
    def valid_username(self,username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return username and USER_RE.match(username)

    
    def valid_password(self,password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return password and PASS_RE.match(password)

    
    def valid_email(self,email):
        EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
        return not email or EMAIL_RE.match(email)
    
    def write_form(self, user_name='', password_1='', password_2='', email='', error=''):
        self.response.out.write(signup_page % {'user_name': user_name, 'password_1' : password_1, 'password_2' : password_2, 'email' : email, 'error' : error })
    def get(self):
        self.write_form()    
    def post(self):
        user_name = self.request.get('username')
        password_1 = self.request.get('password')
        password_2 = self.request.get('verify')
        email = self.request.get('email')
        if not user_name:
            self.write_form(user_name, password_1, password_2, email, 'User name is empty')
        elif password_1 and password_2:
            if password_1 == password_2:
                if not self.valid_password(password_1):
                    self.write_form(user_name, password_1, password_2, email, 'Not a valid password')
                elif not self.valid_username(user_name):
                    self.write_form(user_name, password_1, password_2, email, 'Not a valid user name')
                elif not self.valid_email(email):
                    self.write_form(user_name, password_1, password_2, email, 'Not a valid email address')
                else:
                    u = User.by_name(user_name)
                    if u:
                        self.write_form(user_name, password_1, password_2, email, 'This user already exists')
                    else:
                        user = self.add_user(user_name, password_1, email)
                        self.login(user)
                        self.redirect('/') 
            else:
                    self.write_form(user_name, password_1, password_2, email, 'Passwords dont match')
        else:
            self.write_form(user_name, password_1, password_2, email, 'One of the password field is empty')
              
    def add_user(self,user_name, password, email):
        user = User(user_name=user_name, password=password, email=email)
        user.put()
        return user

class LoginHandler(WikHandler):
    def write_form(self, user_name='', password='', error=''):
        self.response.out.write(login_page % {'user_name': user_name, 'password' : password, 'error' : error })
    def get(self):
        self.write_form()    
    def post(self):
        user_name = self.request.get('username')
        password = self.request.get('password')
        if not user_name:
            self.write_form(user_name, password, 'User name is empty')
        elif not password:
            self.write_form(user_name, password, 'Password is empty')
        else:
            u = User.login(user_name, password)
            if u:
                self.login(u);
                self.redirect('/')
            else:
                self.write_form(user_name, password, 'User name or password is invalid')
                
class LogoutHandler(WikHandler):
    def get(self):
    	if self.request.query_string:
    		title = self.request.query_string.split('=')[1]
    	else:
    		title = ''
        self.logout()
        self.redirect('/' + title)   
 
#app = webapp2.WSGIApplication([('/', WikiPageHandler), ('/signup', SignupHandler), ('/login', LoginHandler), ('/logout', LogoutHandler), ], debug=True)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout*', LogoutHandler),
                               (r'.*', WikiPageHandler)
                               ], 
                               debug=False)   
    
