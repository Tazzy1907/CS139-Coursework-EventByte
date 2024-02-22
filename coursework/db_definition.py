from datetime import datetime
from typing import List
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug import security
# from sqlalchemy.orm import Mapped

# Create the database interface.
db = SQLAlchemy()

# Create the User model.
class User(UserMixin, db.Model):
    __tablename__ = "users"
    userClass = db.Column(db.String(10))
    user_id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique = True)
    email = db.Column(db.Text(), unique = True)
    hashedPass = db.Column(db.Text())

    def __init__(self, username, email, hashedPass, userClass="standard"):
        self.userClass = userClass
        self.username = username
        self.email = email
        self.hashedPass = hashedPass

    def get_id(self):
        return self.user_id


# Create the Event model.
class Event(db.Model):
    __tablename__ = "events"
    event_id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(20))
    dateTime = db.Column(db.DateTime)
    duration = db.Column(db.Integer) # Minutes
    capacity = db.Column(db.Integer)
    ticketsSold = db.Column(db.Integer)
    location = db.Column(db.String(50))


    def __init__(self, name, dateTime, duration, capacity, location, ticketsSold=0):
        self.name = name
        self.dateTime = dateTime
        self.duration = duration
        self.capacity = capacity
        self.location = location

        self.ticketsSold = ticketsSold


# Create the Attendees table, which links the above two tables.
class Ticket(db.Model):
    __tablename__ = "ticket"
    booking_ref = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.user_id))
    event_id = db.Column(db.Integer, db.ForeignKey(Event.event_id))
    status = db.Column(db.String(30)) # Cancelled, Upcoming, etc.


    def __init__(self, user_id, event_id, status="Upcoming"):
        self.user_id = user_id
        self.event_id = event_id
        self.status = status

def dbInit():
    # Add the super user to the database.
    db.session.add(User("super", "super@super.com", security.generate_password_hash("adminPassword"), "super"))
    db.session.add(User("tazzy", "tanlinsir@gmail.com", security.generate_password_hash("taz")))
    db.session.add(Event("CompCafe", datetime(2024, 5, 5, 20, 30, 5), 240, 500, "CS0.06"))
    db.session.add(Event("Careers Fair", datetime(2024, 5, 5, 20, 30, 5), 360, 800, "Rootes Building"))
    db.session.add(Event("Xmas Social", datetime(2023, 5, 5, 20, 30, 5), 90, 300, "Department of Computer Science"))
    db.session.add(Event("Circling", datetime(2024, 5, 5, 20, 30, 5), 120, 300, "Assembly, Leamington"))
    db.session.add(Event("Lightning Talk", datetime(2024, 5, 5, 20, 30, 5), 60, 300, "MS1.13"))

    # Add an example link between the first event and the super-user.
    db.session.add(Ticket(User.query.filter_by(username="tazzy").first().user_id, Event.query.filter_by(name="CompCafe").first().event_id, "Upcoming"))
    db.session.add(Ticket(User.query.filter_by(username="tazzy").first().user_id, Event.query.filter_by(name="Careers Fair").first().event_id, "Cancelled"))
    db.session.add(Ticket(User.query.filter_by(username="tazzy").first().user_id, Event.query.filter_by(name="Xmas Social").first().event_id, "Upcoming"))
    db.session.add(Ticket(User.query.filter_by(username="tazzy").first().user_id, Event.query.filter_by(name="Lightning Talk").first().event_id, "Upcoming"))

    # Commit all changes to the database file.
    db.session.commit()

