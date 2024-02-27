# README and VIDEO
##  EVENTBYTE - Taz Siriwardena

The application submitted is a web-application run on Python-Flask, HTML, and JQuery. The application makes use of all things flask, including flask-mail, flask-login, and its commonly associated security measures.

### Overview
The application allows users to view and sign up to events that are organised by a singular admin user. The singular admin user's details are hard-stored into the database during the initialisation of the database. Any user of the application is free to view all events that are upcoming in real time. They can view the name of the event, the date, the location, and its duration. They are not able to view the number of tickets remaining; this is only visible once less than 5% of tickets are remaining. Users **cannot** book tickets without first registering.

### Registration
In order to register, a user must have a unique username, unique email, and a password. Both the email and the username are checked to make sure that they do not already exist within the database. The user is also asked to confirm their password, and if all input is correct and valid, the user is sent an email in order to validate their email and ensure that it is in fact their own email they are attempting to register with. The user is not added to the database until this email has been validated.

The email sends a URL consisting of a uniquely generated token, using the `itsdangerous` package. This package allows unique, time-sensitive tokens to be generated, and is often used within Python web applications alongside `Flask`. When the user clicks this link in their email, they are redirected to the home page where they are informed that they have been successfully registered. This is, of course, provided the token was in fact valid. They are then encouraged to sign in.

Passwords are stored in the database in hashed form, using the security model `werkzeug` and its hashing algorithm. This ensures that passwords are stored securely, and not even the admin will have access to them.

### Signed In Users
Once signed in, users are free to view all upcoming events as they were when signed out. Upon clicking on an event, the user is able to purchase a ticket provided there are seats remaining. Once purchased, the user is able to see this event in the `My Events` page, where all upcoming events are displayed, as well as any they have cancelled, and events that have already occured that they had a ticket for. Additionally, when a ticket is bought, the user is sent an email confirmation with details of the event, and a uniquely generated barcode using the `EAN13` barcode module. In their `My Events` page, users are also able to view these details, along with the barcode for their respective event, in the case their email gets lost. Upon cancelling an event, the event is moved to the `Cancelled Events` section. All sections can be hidden via pressing a button located over the title of each heading.

### The superuser
The superuser is the admin of the program, and is able to create, delete, and edit the capacity of events. They are able to do this for all events, other than events that have already occured *(AKA those in the past)*. When creating an event, the superuser can only create events with a capacity of at least 10 people, and events cannot be set in the past. Events *can* have the same name as one another, but will still have unique IDs when stored within the database, ensuring their details and respective tickets aren't confused. 

Once an event has been created, it is stored within the database and will be viewable in the home page, where users can then purchase tickets. When editing an event, only the capacity can be changed as per the specification of the application, and the new capacity cannot be less than the number of tickets already sold. When set, this number is updated within the database.

The superuser is also able to delete events, and view all event attendees. When viewing event attendees, a table with every user that has purchased tickets to the event is shown. This includes details such as their username, ID, email and booking reference *(ticket reference)*. This is useful should the admin ever need to contact individuals attending. When an event is deleted, an email is sent out to all those with non-cancelled tickets regarding the event and its cancellation. The event is then deleted from the database, ensuring it doesn't continue to display on the homepage.

Finally, the superuser is able to view an admin log. This button, located on the navbar of the web application, downloads a text file with a log of all major events to occur on the application. I used a text file as I felt it was more versatile than having the information being displayed on a webpage. The admin log contains information such as the userID, eventID, exact time and date, and any other information that is deemed necessary regarding events such as registration, logging in and out, the creation and deletion of events, etc. This gives the admin a tool to make sure everything major is recorded.]

*For the sake of this demo, the login details of the superuser are `super` and `adminPassword` for the username and password respectively.*

### The Database
The database file is composed of three tables; Users, Events, and Tickets. Tickets act as a useful joining tables between the Users and Events tables, and acts as a way to mitigate the "Many-To-Many" relationship that the User and Event tables would've had. All queries take full advantage of SQL and its speed, choosing to evaluate results using SQL rather than grabbing all data and then sorting it through Python.


### A complete application
To conclude, I believe this application has met the specification by implementing all functionality using Python, Flask and Flask-SQLAlchemy with sqlite3. JavaScript in the form of JQuery is used where necessary in order to make the website more visually appealing; the key examples of this are in the `Home` page and `My Events` page. JQuery was also used to be able to hide specific rows of data in the `My Events` page for a cleaner experience. Furthermore, a consistent styling is very apparent across the application, and this is in large thanks to a stylesheet that was used across all HTML pages, as well as using features of Jinja2 such as `extends` and `block`. These were used to base the entire application off of a `base.html`, and worked well to control the masses of repeated code that may have otherwise been present when declaring HTML pages.

Regarding usability and accessibility, all clickable links within the app are clickable buttons. This allows non-mouse users to navigate through all pages using just the TAB key should this be necessary. The colours chosen for the style are also bright and "pop", which should be apparent and make things easier to read. Furthermore, nearly all buttons are highlighted upon hover, making it very obvious to the user what can be pressed and what cannot.

Every attempt has been made to lessen any existing security issues; As mentioned before, all passwords are hashed and a `secret_key` is used to generate the tokens which again, have an expiry timer so that they cannot be used indefinitely. Any pages that are only accessible to admins have entry checks for whenever the website is loaded to make sure that an admin actually is logged in, else the user is redirected elsewhere. Furthermore, both GET and POST methods are used to make sure no users are trying to bypass forms to get to a route. 

Before submitting your coursework, run `./clean.sh` as this will remove the virtual environment which can be reconstructed locally.



