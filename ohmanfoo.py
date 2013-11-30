import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.api import urlfetch
from google.appengine.api import mail
from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
def valid_username(username):
    return username and USER_RE.match(username)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
PASS_RE = re.compile(r"^.{3,20}$")

def valid_password(password):
    return password and PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def make_secure_eval(val):
    return '%s;%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def check_secure_eval(secure_val):
    val = secure_val.split(';')[0]
    if secure_val == make_secure_val(val):
        return val

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def invites_key(group = 'default'):
    return db.Key.from_path('invites', group)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class OhmanHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class User(db.Model):

    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    @classmethod
    def register(cls, name, pw, email):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Invite(db.Model):

    fname = db.StringProperty(required = True)
    lname = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    psize = db.IntegerProperty(required = True)
    auth_id = db.StringProperty(required = True)
    auth_flag = db.BooleanProperty()

    def render(self):
        return render_str("invite.html", i = self)

    @classmethod
    def by_auth_id(cls, auth_id):
        i = Invite.all().filter('auth_id=', auth_id).get()
        return i

    @classmethod
    def by_email(cls, email):
        i = db.GqlQuery("SELECT * FROM Invite " +
                        "WHERE email = :1 ", email)
        return i.get()

    @classmethod
    def confirm(cls, email):
        i = cls.by_email(email)
        i.auth_flag = True
        return i.put()

    @classmethod
    def add_invite(cls, fname, lname, email, psize):
        name = fname + lname
        auth_id = make_secure_val(email)
        return Invite(parent = invites_key(),
                      fname = fname,
                      lname = lname,
                      email = email,
                      psize = psize,
                      auth_id = auth_id,
                      auth_flag = False)

    @classmethod    
    def send_mail(cls, email, auth_id):
        if email != None:
            #if not auth_flag == False:
            #   pass
            #else:            
            sender_address = "<rsvp.karenandles@gmail.com>"
            subject = "You Are Invited!"
            message = mail.EmailMessage(sender=sender_address,
                                        subject=subject)
            user_address = email

            img_name = 'Karen_and_Les_Wedding_Invite.jpg'
            message.to = user_address
            message.attachments = [(img_name, invite_jpg)]
            confirmation_url = cls.createNewUserConfirmation(user_address, auth_id)
            message.body = """            
Come celebrate the union of Karen and Les this July with us, 


Fri 12 July 2013



When you are ready to confirm your attendance please click the link below. 
            %s
            """ % confirmation_url

            message.html = """
<p> Come celebrate the union of Karen and Les this July with us, </p>

<p> Fri 12 July 2013 </p>


<p> When you are ready to confirm your attendance please click the link below. </p>


<a href='%s'> Click here to confirm your attendance.</a>
        """ % confirmation_url

            message.send()

        else:
            msg = "there's no email!"
            self.render('/admin/rsvplist.html')
    @classmethod
    def createNewUserConfirmation(cls, email, auth_id):
        url = "http://karenandlesrsvp.appspot.com"
        #auth_token = auth_id.split(';')[1]
        confirmation_url = url + "/confirmation?q=" + auth_id

        return confirmation_url

class SignupInvite(OhmanHandler):

    def get(self):
        if self.user:
            order_by = self.request.get('order')
            invites = Invite.all()
            if not order_by:
                invites.order("fname")
            elif order_by == 'name':
                invites.order("lname")
            elif order_by == 'confirmed':
                invites.order("auth_flag")
            elif order_by == 'party':
                invites.order("psize")

            self.render("/admin/rsvplist.html", invites = invites)
        else: 
            self.redirect('/')

    def post(self):
        have_error = False
        self.firstname = self.request.get('firstname')
        self.lastname = self.request.get('lastname')        
        self.email = self.request.get('email')
        params = dict(firstname = self.firstname,
                      lastname = self.lastname,
                      email = self.lastname)
        if not valid_username(self.firstname):
            params['error_firstname'] = "That's not a name."
            have_error = True
        if not valid_username(self.lastname):
            params['error_lastname'] = "That's not a name."
            have_error = True
        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        if have_error:
            self.render('/admin/register.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class RegisterInvite(SignupInvite):

    def done(self):
        email = self.email
        u = Invite.all().filter('email =', email).get()
        if u:
            msg = 'Email already registered'
            self.render('admin/new_invitee.html', error = msg)
        else:
            u = Invite.add_invite(self.firstname, self.lastname, self.email)
            u.put()
            u.send_mail(self.email, u.auth_id)
            self.redirect('/admin/register')

class SelfSignupInvite(OhmanHandler):
    def get(self):
        self.render("new_self_invitee.html")

    def post(self):
        have_error = False
        self.firstname = self.request.get('firstname')
        self.lastname = self.request.get('lastname')        
        self.email = self.request.get('email')
        self.psize = int(self.request.get('psize'))
        params = dict(firstname = self.firstname,
                      lastname = self.lastname,
                      email = self.lastname)
        if not valid_username(self.firstname):
            params['error_firstname'] = "That's not a name."
            have_error = True
        if not valid_username(self.lastname):
            params['error_lastname'] = "That's not a name."
            have_error = True
        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        if have_error:
            self.render('/new_self_invitee.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class SelfRegisterInvite(SelfSignupInvite):

    def done(self):
        email = self.email
        u = Invite.all().filter('email =', email).get()
        if u:
            msg = 'Email already registered'
            self.render('/new_self_invitee.html', error = msg)
        else:
            u = Invite.add_invite(self.firstname, self.lastname, self.email, self.psize)
            u.put()
            u.send_mail(self.email, u.auth_id)
            self.redirect('/')

class Signup(OhmanHandler):

    def get(self):
        if self.user:
            self.render("signup-form.html")
        else:
            self.redirect("/")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):

    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/admin/register')

class Login(OhmanHandler):

    def get(self):
        if not self.user:
            self.render('login-form.html')
        else:
            self.redirect('/')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/admin/register')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(OhmanHandler):

    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(OhmanHandler):

    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

class Post(db.Model):

    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
#rsvp stuff

class ConfirmInvite(OhmanHandler):
    def get(self):
        auth_id = self.request.get('q')
        if auth_id:
            email = check_secure_val(auth_id)
            if email:
                i = Invite.by_email(email)
                if i:
                    if i.auth_flag == False:
                        self.render('confirmation.html', message = 'Confirm?')
                    else:
                        self.redirect('/')
                else:
                    self.redirect('/')
            else:
                self.redirect('/')
        else:
            self.redirect('/')
    def post(self):
        confirmation = self.request.get("Yes")
        auth_id = self.request.get('q')
        email = check_secure_val(auth_id)
        i = Invite.by_email(email)
        if confirmation == "Yes":
            i.confirm(email)
            self.render('/confirmation.html', message = 'Thank you!')
            self.redirect('/')
        else:
            self.render('/confirmation.html', message = 'Thank you!')
            self.redirect('/')

class InviteImages(OhmanHandler):

    def get(self):
        self.render("invite.html")

class MainPage(OhmanHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.render('base.html')

application = webapp2.WSGIApplication([('/', MainPage),
                               #('/confirmation', ConfirmInvite),
                               #('/blog/?', RSVPFront),
                               #('/invite', InviteImages),
                               #('/blog/([0-9]+)', PostPage),
                               #('/blog/newpost', NewPost),
                               #('/signup', Register),
                               #('/login', Login),
                               #('/logout', Logout),
                               #('/register', SelfRegisterInvite),
                               #('/unit3/welcome', Unit3Welcome),
                               #('/admin/register', RegisterInvite),
                               ],
                              debug=True)