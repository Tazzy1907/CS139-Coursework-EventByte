from flask import Flask, render_template, flash, session, redirect, request
from db_definition import db, User, Event, Ticket, dbInit
from werkzeug import security
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from sqlalchemy.exc import IntegrityError
from sqlalchemy import update
import datetime
from createBarcode import createBarcode

app = Flask(__name__)

app.config['SECRET_KEY'] = 'tazzy'

# USE @LOGIN_REQUIRED ABOVE ANY ROUTE TO MAKE IT ACCESSIBLE ONLY TO LOGIN USERS.
# https://flask-login.readthedocs.io/en/latest/#flask_login.LoginManager.login_view


# App configuration, standard code.
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///eventbyte.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Login Manager Stuff, standard code.
loginManager = LoginManager()
loginManager.init_app(app)
loginManager.login_view = "logIn"

@loginManager.user_loader
def loadUser(user_id):
    return User.query.get(int(user_id))

# True resets the database everytime the app is restarted.
resetDB = True
if resetDB:
    with app.app_context():
        # Delete (drop) everything, re-create the tables, then put some data into the tables using dbInit.
        db.drop_all()
        db.create_all()
        dbInit()

# For when someone only loads the first part of the URL. Take to home page if logged in, if not then ask to log in.
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect('/home')
    else:
        flash("Log in or register to get started")
        return redirect('/login')

# Route to the registration page.    
@app.route('/register', methods=['GET', 'POST'])
def register():

    # User is already logged in, go straight to the home page.
    if current_user.is_authenticated:
        return redirect('/home')

    if request.method == "POST":
        email = request.form['email']
        name = request.form['username']
        password = request.form['password']
        confirmPass = request.form['cpassword']

        # The entered fields are not valid.
        if not registrationAuthentication(name, email, password, confirmPass):
            return redirect('/register')
        
        passwordHash = security.generate_password_hash(password)
        
        # Attempt to add user to the database.
        try:
            newUser = User(name, email, passwordHash)
            db.session.add(newUser)
            db.session.commit()
        except IntegrityError as err:
            db.session.rollback()
            flash("Could not register" + str(err))
            return redirect('/register')
        
        # User has been added to the database.
        flash("You have registered successfully, you may now log in")
        writeAdminLog("register", 0, 0, newUser.user_id)

        return redirect('/login')

    # Website has been reloaded, etc. Not a form submission.
    if request.method == "GET":
        return render_template('register.html')


# Route to the login page.
@app.route('/login', methods=['GET', 'POST'])
def logIn():

    # User is already logged in, go straight to the home page.
    if current_user.is_authenticated:
        return redirect('/home')
    
    # Form submission, so look for the input username in the database.
    if request.method == "POST":
        name = request.form['username']
        password = request.form['password']

        # Nothing entered for username
        if name == '':
            flash('Username cannot be empty')
            return redirect('/login')

        user = User.query.filter_by(username=name).first()

        # User not found in the database, so refresh page.
        if user is None:
            flash('Could not find username, try again')
            return redirect('/login')
        
        # User found but database password does not match hashed version of input password.
        if not security.check_password_hash(user.hashedPass, password):
            flash('Your password does not match your username, try again')
            return redirect('/login')
        
        # Login successful.
        login_user(user)
        writeAdminLog("logIn", 0, 0, current_user.user_id)

        if current_user.userClass == "super":
            return redirect('/superHome')
        else:
            return redirect('/home')

    # Website has been reloaded, etc. Not a form submission.
    if request.method == "GET":
        return render_template('login.html')


# The admin home page.
@app.route('/superHome')
def superHome():
    if (not current_user.is_authenticated) or (current_user.userClass != "super"):
        flash("Only admins can access this page.")
        return redirect('/home')
    
    updateTickets()
    
    return render_template('superHome.html', events=Event.query.all(), currTime = datetime.datetime.now())


# Route to the home page.
@app.route('/home')
def home():

    updateTickets()
    events=Event.query.all()

    # NEED TO CHECK IF AN EVENT IS OWNED BY THE USER.

    return render_template('home.html', events=events, currTime = datetime.datetime.now())


# Log the user out.
@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        flash('You have successfully logged out')
        writeAdminLog("logOut", 0, 0, current_user.user_id)
    logout_user()
    return redirect('/login')


# The about page
@app.route('/about')
def about():
    return render_template('about.html')


# View an event in more depth from the home page.
@app.route('/viewEvent')
def viewEvent():
    eventID = request.args.get('eventid') or None
    if not eventID:
        return redirect('/')
    else:
        # Get the Event object for this event.
        thisEvent = Event.query.filter_by(event_id=int(eventID)).first()

        # Only consider ownership of the event if the user is logged in.
        if current_user.is_authenticated:
            # Check if the user already owns a ticket for this event.
            getTicket = Ticket.query.filter(Ticket.event_id == eventID, Ticket.user_id == current_user.user_id, Ticket.status !='Cancelled').first()

            # Check if ticket can be bought / cancelled for this event.
            if thisEvent.dateTime > datetime.datetime.now():
                upcomingEvent = True
                if getTicket is None:
                    eventOwned = False
                else:
                    eventOwned = True
            else:
                eventOwned = False
                upcomingEvent = False
        else:
            eventOwned = False
            upcomingEvent = False

        if eventOwned:
            print(getTicket.booking_ref)
            createBarcode(getTicket.booking_ref)

        return render_template('viewEvent.html', event=thisEvent, eventOwned=eventOwned, upcomingEvent=upcomingEvent)


# The route to when a ticket is attempting to be purchased.
@app.route('/buyTicket', methods=['POST', 'GET'])
def buyTicket():
    if request.method == "POST":
        eventID = request.form['eventID']

        if not eventID:
            return redirect('/')
        
        # Check whether the ticket already exists in the database.
        try:
            ticket = Ticket.query.filter(Ticket.event_id == eventID, Ticket.user_id == current_user.user_id).first()
            if not ticket:
                # Attempt to add a ticket to the database.
                newTicket = Ticket(current_user.user_id, eventID)
                db.session.add(newTicket)
                db.session.commit()
                flash(f"Ticket has been successfully bought. Thankyou for your purchase.\nTicket Reference: {newTicket.booking_ref}")
                writeAdminLog("ticketBought", eventID, newTicket.booking_ref, current_user.user_id)

            else:
                # Ticket exists so update.
                ticket.status = "Upcoming"
                db.session.commit()
                flash(f"Ticket has been successfully bought. Thankyou for your purchase.\nTicket Reference: {ticket.booking_ref}")
                writeAdminLog("ticketBought", eventID, ticket.booking_ref, current_user.user_id)


        except IntegrityError as err:
            db.session.rollback()
            flash("Could not buy ticket" + str(err))

        # Redirect to the home page with a message confirming or denying purchase.
        return redirect('/home')
    
    if request.method == "GET":
        return redirect('/')


# The route for when a ticket is being cancelled.
@app.route('/cancelTicket', methods=['POST', 'GET'])
def cancelTicket():
    if request.method == "POST":
        eventID = request.form['eventID']

        if not eventID:
            return redirect('/')
        
        # Attempt to update the ticket in the database.
        try:
            ticket = Ticket.query.filter(Ticket.event_id == eventID, Ticket.user_id == current_user.user_id).first()
            ticket.status = "Cancelled"
            db.session.commit()

        except IntegrityError as err:
            flash("Could not cancel ticket " + str(err))
        
        flash("Successfully cancelled event")
        writeAdminLog("ticketCancelled", eventID, ticket.booking_ref, current_user.user_id)
        return redirect('/home')
    

    if request.method == "GET":
        return redirect('/')


# View only the events that have been purchased by the user.
@app.route('/myEvents')
def myEvents():
    if not current_user.is_authenticated:
        return redirect('/')
    
    # Update all tickets.
    updateTickets()

    # Return the events that match the user_id in the Ticket database table.
    completedEvents = db.session.query(Event).join(Ticket, Event.event_id == Ticket.event_id).where(Ticket.user_id == current_user.user_id).where(Ticket.status == "Completed")
    cancelledEvents = db.session.query(Event).join(Ticket, Event.event_id == Ticket.event_id).where(Ticket.user_id == current_user.user_id).where(Ticket.status == "Cancelled")
    upcomingEvents = db.session.query(Event).join(Ticket, Event.event_id == Ticket.event_id).where(Ticket.user_id == current_user.user_id).where(Ticket.status == "Upcoming")
    
    return render_template('boughtEventsView.html', completedEvents=completedEvents, cancelledEvents=cancelledEvents, upcomingEvents=upcomingEvents, currTime = datetime.datetime(datetime.MINYEAR, 1, 1))


# Route to create an event. Only accessible to admins.
@app.route('/createEvent', methods=["GET", "POST"])
def createEvent():
    if not current_user.is_authenticated or current_user.userClass != "super":
        flash("Only accessible to admins.")
        return redirect('/')
    
    if request.method == "POST":
        # Get all form fields. 
        name = request.form['eventName']
        date = request.form['eventDate']
        time = request.form['eventTime']
        duration = request.form['eventDur']
        capacity = request.form['eventCap']
        location = request.form['eventLoc']

        # Create a Python datetime instance.
        if date == "" or time == "":
            flash("You cannot have an empty field.")
            return redirect('/createEvent')
        else:
            newDateTime = datetime.datetime.combine(datetime.date(year=int(date[:4]), month=int(date[5:7]), day=int(date[8:])), datetime.time(hour=int(time[:2]), minute=int(time[3:])))

        # Check all fields are valid.
        if not newEventAuthentication(name, newDateTime, duration, capacity, location):
            return redirect('/createEvent')
        
        # All tests have been passed.
        try:
            newEvent = Event(name, newDateTime, int(duration), int(capacity), location)
            db.session.add(newEvent)
            db.session.commit()
        except IntegrityError as err:
            flash("Could not create event " + str(err))
            return redirect('/')
        
        flash("Event has been succesfully added.")
        writeAdminLog("createEvent", newEvent.event_id, 0, current_user.user_id)
        return redirect('/')
    
    # For non-form website loading.
    if request.method == "GET":
        return render_template("createEvent.html")


# Route to edit the event. Only accessible to admins.
@app.route('/editEvent', methods=["GET", "POST"])
def editEvent():
    # Make sure only admins can view this page. 
    if not current_user.is_authenticated or current_user.userClass != "super":
        flash("Only accessible to admins.")
        return redirect('/')
    
    # Admins should be able to edit the capacity. They can only edit if the number of tickets sold is less than
    # the capacity.
    if request.method == "GET":
        eventID = request.args.get("eventid") or None

        if not eventID:
            return redirect('/')
        
        thisEvent = Event.query.filter_by(event_id=eventID).first()

        return render_template('editEvent.html', event=thisEvent)
    
    if request.method == "POST":
        # Validate whether the new capacity is viable.
        eventID = request.form["eventID"]
        newCap = request.form["newCapacity"]
        thisEvent = Event.query.filter_by(event_id=eventID).first()
        currCap = thisEvent.capacity
        
        # If the field is left blank.
        if newCap == "":
            flash("Please enter a value.")
            return redirect(f"/editEvent?eventid={eventID}")
        
        # Make sure the input is a valid number.
        try:
            int(newCap)
        except ValueError as err:
            flash("Please enter a valid number.")
            return redirect(f'/editEvent?eventid={eventID}')

        # When the new capacity is not a viable number.
        if int(newCap) < thisEvent.ticketsSold:
            flash("The new capacity cannot be less than the number of tickets already sold.")
            return redirect(f'/editEvent?eventid={eventID}')
        
        # The new capacity must be at least 10
        elif int(newCap) < 10:
            flash("Events cannot have a capacity less than 10.")
            return redirect(f'/editEvent?eventid={eventID}')
        # If the number is viable, then update the database.
        else:
            try:
                thisEvent.capacity = int(newCap)
                db.session.commit()
                flash("Event has been edited.")
                writeAdminLog("editEvent", thisEvent.event_id, 0, current_user.user_id, f"Capacity {newCap} from {currCap}")
            except IntegrityError as err:
                flash("Could not update capacity " + str(err))

        return redirect('/')   


# Route to view event attendees. Only accessible to admins.
@app.route('/viewEventAttendees')
def viewEventAttendees():
    # Make sure only admins can view this page. 
    if not current_user.is_authenticated or current_user.userClass != "super":
        flash("Only accessible to admins.")
        return redirect('/')
    
    eventID = request.args.get("eventid") or None

    if not eventID:
        return redirect('/')
    
    # Return the users that match the event_id in the Ticket database table.
    attendees = db.session.query(User, Ticket.booking_ref).join(Ticket, User.user_id == Ticket.user_id).where(Ticket.event_id == eventID).where(Ticket.status != "Cancelled")

    for row in attendees:
        print(row)


    return render_template("attendeeList.html", attendees=attendees, event=Event.query.filter_by(event_id=eventID).first())


# Route to delete an event. Only accessible to admins.
@app.route('/deleteEvent')
def deleteEvent():
    if not current_user.is_authenticated or current_user.userClass != "super":
        flash("Only accessible to admins.")
        return redirect('/')
    
    eventID = request.args.get("eventid") or None

    if not eventID:
        return redirect('/')

    # Add a confirmation box.

    # First try find the event. If not, redirect to previous page. Also delete all tickets that exist.
    Event.query.filter_by(event_id = eventID).delete()
    Ticket.query.filter_by(event_id = eventID).delete()

    db.session.commit()

    flash(f"Event {eventID} has been deleted.")
    writeAdminLog("deleteEvent", eventID, 0, current_user.user_id)
    return redirect('/')


# Route tocurrTime = datetime.datetime.now() to authenticate a new event being added.
def newEventAuthentication(name, newDateTime, duration, capacity, location):
    # All must be non empty.
    # Date time must be in the future.
    # Capacity must be more than 10.
    # Capacity and duration must be integers.

    # Check all fields are non empty.
    inputNames = ['eventName', 'eventDur', 'eventCap', 'eventLoc']
    for name in inputNames:
        if request.form[name] == "":
            flash("You cannot have an empty field")
            return False
    
    # Check capacity and duration are integers.
    try:
        int(capacity)
        int(duration)
    except ValueError:
        flash("Please enter valid numbers for capacity and duration.")
        return False
    
    # Check capacity is at least 10.
    if int(capacity) < 10:
        flash("Your event must at least have a capacity of 10.")
        return False
    
    # Check date time is in the future.
    if newDateTime <= datetime.datetime.now():
        flash("Your event must take place in the future.")
        return False

    return True


# Function to authenticate registration
def registrationAuthentication(username, email, password, cpassword):
    # All must be non empty.
    # Username must be unique.
    # Password and cpassword must be equal.
    # Email must be valid.

    # Checks all fields are non empty.
    if ((username == '') or (email == '') or (password == '')):
        flash("You cannot have an empty field")
        return False
    
    # Checks that the username does not already exist in the database.
    existingUser = User.query.filter_by(username=username).first()
    if existingUser is not None:
        flash("That username already exists, choose a different one")
        return False
    
    # Checks that the email does not already exist in the database.
    existingEmail = User.query.filter_by(email=email).first()
    if existingEmail is not None:
        flash("That email is already in use, please use a different one.")
        return False
    
    # Checks that the password field matches the confirm password field.
    if (password != cpassword):
        flash('Your passwords must be the same')
        return False

    # Checks that the email contains an '@' sign
    if '@' not in email:
        flash('Your email is invalid')
        return False
    
    # If all tests passed, return true.
    return True


# Procedure to update all tickets and events to have up-to-date values.
def updateTickets():
    events = Event.query.all()

    for event in events:
        # Update all events to record the number of tickets that have been sold.
        ticketNum = db.session.query(Ticket).where(Ticket.event_id == event.event_id, Ticket.status == "Upcoming").count()
        event.ticketsSold = ticketNum
        
        # Update all tickets so that if they're past the current date / time, they become "Completed" events.
        if event.dateTime <= datetime.datetime.now():
            tickets = db.session.query(Ticket).where(Ticket.event_id == event.event_id)
            for ticket in tickets:
                ticket.status = "Completed"

    db.session.commit()


# Procedure to write to the admin file.
def writeAdminLog(eventType, eventID, ticketID, user_id, otherNotes=""):
    '''
    Parameters:
    Type of event - Create / Delete / Buy Ticket / Cancel Ticket / Registration / Login
    UserID
    Possibly EventID
    Possibly TicketID
    '''

    # Open text file with append.
    f = open("adminLog.txt", "a")

    # Possible actions to view.
    if eventType == "logIn":
        f.write(f"\n|\t LOGIN\t\t|\t {user_id}\t\t|\t N/A\t\t|\t N/A\t\t|\t {datetime.datetime.now()}\t\t|\t NONE\t\t|")

    if eventType == "register":
        f.write(f"\n|\tREGISTER\t|\t {user_id}\t\t|\t N/A\t\t|\t N/A\t\t|\t {datetime.datetime.now()}\t\t|\t NONE\t\t|")

    if eventType == "logOut":
        f.write(f"\n|\t LOGOUT\t\t|\t {user_id}\t\t|\t N/A\t\t|\t N/A\t\t|\t {datetime.datetime.now()}\t\t|\t NONE\t\t|")

    if eventType == "createEvent":
        f.write(f"\n| CREATE EVENT  |\t {user_id}\t\t|\t {eventID}\t\t|\t N/A\t\t|\t {datetime.datetime.now()}\t\t|\t NONE\t\t|")

    if eventType == "deleteEvent":
        f.write(f"\n| DELETE EVENT  |\t {user_id}\t\t|\t {eventID}\t\t|\t N/A\t\t|\t {datetime.datetime.now()}\t\t|\t NONE\t\t|")

    if eventType == "editEvent":
        f.write(f"\n|  EDIT EVENT   |\t {user_id}\t\t|\t {eventID}\t\t|\t N/A\t\t|\t {datetime.datetime.now()}\t\t|\t {otherNotes}\t\t|")

    if eventType == "ticketBought":
        f.write(f"\n| TICKET BOUGHT |\t {user_id}\t\t|\t {eventID}\t\t|\t {ticketID}\t\t|\t {datetime.datetime.now()}\t\t|\t NONE\t\t|")

    if eventType == "ticketCancelled":
        f.write(f"\n| TICKET CANCEL |\t {user_id}\t\t|\t {eventID}\t\t|\t {ticketID}\t\t|\t {datetime.datetime.now()}\t\t|\t NONE\t\t|")


    # Once file has been written to.
    f.close()


