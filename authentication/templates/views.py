from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from .forms import BlogForm
from .models import Blogs
from django.shortcuts import get_object_or_404
from django.core.paginator import Paginator
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth.models import User
from validate_email import validate_email
from django.core.exceptions import MultipleObjectsReturned
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import generate_token
from django.conf import settings
from django.core.mail import EmailMessage
import threading

# Create your views here.

class EmailThread(threading.Thread):
    def __init__(self, email_send):
        self.email_send = email_send
        threading.Thread.__init__(self)

    def run(self):
        self.email_send.send()
    


def home(request):
    return render(request, 'home.html')

def signupp(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(request,username = username, password = password)
            login(request,user)
            return redirect('blogs')
        else:
            print(form.errors)
            return render(request, 'signupp.html', {'form': form})
    else:
        form = UserCreationForm()
    return render(request, 'signupp.html', {'form': form})


@login_required(login_url='/login/')
def userblogs(request):
    return render(request, 'userblog.html')


def logoutt(request):
    if request.method == "POST":
        logout(request)
        return redirect('home')


def loginuser(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request,user)
            return redirect('blogsview')
        else:
            return render(request, 'loginuser.html', {'form': AuthenticationForm(), 'error': 'Incorrect username or password'})

    else:
        return render(request, 'loginuser.html', {'form': AuthenticationForm()})



# @login_required(login_url='/login/')
# def blogcreate(request):
#     if request.method =="GET":
#         return render(request,'blogcreate.html',{'form': BlogForm()})

#     else:
#         try:
#             form = BlogForm(request.POST)
#             if form.is_valid():
#                 obj = form.save(commit=False)
#                 obj.user = request.user
#                 obj.save()
#                 return redirect('blogsview')
        
#         except ValueError:
#             return render(request,'blogcreate.html',{'form': BlogForm(), 'error': 'Word Limit Exceeded!'})


@login_required(login_url='/login/')
def blogcreate(request):
    if request.method =="GET":
        return render(request,'blogcreate.html',{'form': BlogForm()})

    else:
        form = BlogForm(request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.user = request.user
            obj.save()
            return redirect('blogsview')
        
        else:
            return render(request,'blogcreate.html',{'form': BlogForm(), 'error': 'Word Limit Exceeded!'})

def blogsview(request):
    blogs = Blogs.objects.filter(user=request.user, completed=False)

    paginator = Paginator(blogs, 4) 

    page_number = request.GET.get('page')
    blogs = paginator.get_page(page_number)
    return render(request,'blogsview.html',{'blogs': blogs})


def blogupdate(request,id):
    blog = get_object_or_404(Blogs, pk=id, user=request.user)
    if request.method == "GET":
        form = BlogForm(instance=blog)
        return render(request,'blogupdate.html',{'form': form, 'blog': blog})

    else:
        form = BlogForm(request.POST, instance=blog)
        if form.is_valid():
            form.save()
            return redirect('blogsview')

        else:
            return render(request,'blogupdate.html',{'form': form, 'blog': blog, 'error': 'Word Limit Exceeded!'})

def deleteblog(request,id):
    blog = get_object_or_404(Blogs, pk=id, user=request.user)
    blog.delete()
    return redirect('blogsview')

def complete(request,id):
    blog = get_object_or_404(Blogs, pk=id, user=request.user)
    blog.completed = True
    blog.save()
    return redirect('completedblogs')



def completedblogs(request):
    blogs = Blogs.objects.filter(user=request.user, completed=True)[:5]
    return render(request,'completedblogs.html',{'blogs': blogs})


def search(request):

    query = request.GET.get('query')

    queries = query.split(" ")

    blogs = Blogs.objects.filter(Q(title__icontains=query)|Q(description__icontains=query)).distinct()
    
    return render(request,'search.html',{'blogs': blogs})

def signupuser(request):
  if request.method == "GET":
    return render(request,'signupuser.html')

  else:
    context = {
      'data': request.POST,
      'has_error': False,
    }
    
    email = request.POST['email']
    password = request.POST['password']
    password2 = request.POST['password2']
    username = request.POST['username']
    name = request.POST['name']

    if len(password) < 6:
      messages.add_message(request,messages.ERROR,'Password should be minimum six characters long.')
      context['has_error'] = True

    if not validate_email(email):
      messages.add_message(request,messages.ERROR,'Invalid Email')
      context['has_error'] = True

    if password != password2:
      messages.add_message(request,messages.ERROR,"password don't match")
      context['has_error'] = True

    # try:
    #     if User.objects.get(email=email)>0:
    #         messages.add_message(request,messages.ERROR,"Email already exists")
    #         context['has_error'] = True

    # except MultipleObjectsReturned:
    #     messages.add_message(request,messages.ERROR,"Email already exists")
    #     context['has_error'] = True


    try:
        match = User.objects.get(email=email)
        messages.add_message(request,messages.ERROR,"Email already exists")
        context['has_error'] = True
    except Exception as identifier:
        pass
    


    if User.objects.filter(username=username).exists():
        messages.add_message(request,messages.ERROR,"Username Unavailable")
        context['has_error'] = True

    if context['has_error']:
        return render(request,'signupuser.html',context,status=400)

    user = User.objects.create_user(username=username,email=email)
    user.set_password(password)
    user.first_name = name
    user.last_name = name
    user.is_active = False

    user.save()
    messages.add_message(request,messages.SUCCESS,"Account Created")

    current_site = get_current_site(request)
    email_subject = 'Activate Your Account'
    message = render_to_string('activate.html',
        {
        'user': user,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': generate_token.make_token(user),
        }
        )

    email_send = EmailMessage(
    email_subject,
    message,
    settings.EMAIL_HOST_USER,
    [email],

    )

    # email_send.send()

    EmailThread(email_send).start()
    

    return redirect('loginuser')
    # return HttpResponse('Please confirm your email address to complete the registration')


def loginnew(request):
    if request.method == "GET":
        return render(request,'praclogin.html')

    else:
        context= {
            'data': request.POST,
            'has_error': False,
        }

        username = request.POST['username']
        password = request.POST['password']

        if username == "":
            messages.add_message(request,messages.ERROR,"Username is required")
            context['has_error'] = True

        if password == "":
            messages.add_message(request,messages.ERROR,'Password is required')
            context['has_error'] = True

        user = authenticate(request,username=username,password=password)

        if not user and not context['has_error']:
            messages.add_message(request,messages.ERROR,'Invalid login')
            context['has_error'] = True

        if context['has_error']:
            return render(request,'praclogin.html',status=401,context=context)

        login(request,user)
        return redirect('home')



def activate(request,uidb64,token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except Exception as identifier:
        user = None

    if user is not None and generate_token.check_token(user,token):
        user.is_active = True
        user.save()
        messages.add_message(request,messages.INFO,'account activated successfully')
        return redirect('loginuser')
            
    return render(request, 'activate_failed.html')
    





