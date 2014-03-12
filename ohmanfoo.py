
#### Imports module ####


from vartools import *
import webapp2

from google.appengine.api import urlfetch
from google.appengine.api import mail
from google.appengine.ext import db

# main

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

#### User module ####

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

#### Invite/email module ####

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
            sender_address = "<rsvp@gmail.com>"
            subject = "You Are Invited!"
            message = mail.EmailMessage(sender=sender_address,
                                        subject=subject)
            user_address = email

            img_name = 'Wedding_Invite.jpg'
            message.to = user_address
            message.attachments = [(img_name, invite_jpg)]
            confirmation_url = cls.createNewUserConfirmation(user_address, auth_id)
            message.body = "%s" % confirmation_url

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


#### user admin tools ####


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


 #### Invites/Emails Module img tools ####
class InviteImages(OhmanHandler):

    def get(self):
        self.render("invite.html")
  

class MainPage(OhmanHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        self.render('base.html')

application = webapp2.WSGIApplication([('/', MainPage),

                               #('/blog/?', RSVPFront),

                               #('/blog/([0-9]+)', PostPage),
                               #('/blog/newpost', NewPost),
                               #('/signup', Register),
                               #('/login', Login),
                               #('/logout', Logout),
                               #('/register', SelfRegisterInvite),

                               #('/admin/register', RegisterInvite),
                               ],
                              debug=True)
