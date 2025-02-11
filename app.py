from datetime import datetime
import csv
from io import StringIO
from flask import Flask, request, render_template, redirect, url_for, session, flash, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scholarships.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Change this for a real secret key (will do later)
db = SQLAlchemy(app)


# ========================== MODELS ==========================

class FundAllocation(db.Model):
    __tablename__ = 'fund_allocation'
    allocation_id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False)
    scholarship_id = db.Column(db.Integer, db.ForeignKey('scholarship.scholarship_id'), nullable=False)
    amount_allocated = db.Column(db.Float, nullable=False, default=0.0)
    allocated_by = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False)  # Financial aid admin
    allocated_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    student = db.relationship('Student', foreign_keys=[student_id], back_populates='fund_allocations')
    scholarship = db.relationship('Scholarship', foreign_keys=[scholarship_id], backref='fund_allocations')
    admin = db.relationship('Student', foreign_keys=[allocated_by], back_populates='admin_allocations')


class Student(db.Model):
    __tablename__ = 'student'
    student_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True, nullable=False)
    gpa = db.Column(db.Float)
    status = db.Column(db.String(50))
    password = db.Column(db.String(200))
    role = db.Column(db.String(50), default='student')
    inbox = db.relationship('Message', backref='student_inbox', lazy=True)  # Renamed backref
    fund_allocations = db.relationship('FundAllocation', foreign_keys=[FundAllocation.student_id], back_populates='student')
    admin_allocations = db.relationship('FundAllocation', foreign_keys=[FundAllocation.allocated_by], back_populates='admin')


class Scholarship(db.Model):
    __tablename__ = 'scholarship'
    scholarship_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    criteria_gpa = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='open')
    funds_needed = db.Column(db.Float, nullable=False)
    funds_allocated = db.Column(db.Float, default=0)  # Initially 0

class Application(db.Model):
    application_id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False)
    scholarship_id = db.Column(db.Integer, db.ForeignKey('scholarship.scholarship_id', ondelete="SET NULL"), nullable=True)
    status = db.Column(db.String(20), default='pending')
    application_date = db.Column(db.DateTime, default=db.func.current_timestamp())

    student = db.relationship('Student', backref=db.backref('applications', lazy=True))
    scholarship = db.relationship('Scholarship', backref=db.backref('applications', lazy=True))


class Message(db.Model):
    message_id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='unread')
    sent_at = db.Column(db.DateTime, default=db.func.current_timestamp())


class Announcement(db.Model):
    __tablename__ = 'announcement'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AvailableFunds(db.Model):
    __tablename__ = 'available_funds'
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float)

    def __repr__(self):
        return f'<AvailableFunds {self.amount}>'

class FA_Message(db.Model):
    __tablename__ = 'fa_message'
    message_id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('student.student_id'), nullable=False)  # Financial Aid Admin
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    sender = db.relationship('Student', foreign_keys=[sender_id], backref='sent_fa_messages')
    receiver = db.relationship('Student', foreign_keys=[receiver_id], backref='received_fa_messages')

# ========================== DATABASE INIT ==========================

def add_default_users():
    admin_exists = Student.query.filter_by(email='admin@example.com').first()
    if not admin_exists:
        admin = Student(name="Admin", email="admin@example.com", gpa=4.0, status="active",
                        password=generate_password_hash("admin123"), role="admin")
        db.session.add(admin)

    student_exists = Student.query.filter_by(email='student@example.com').first()
    if not student_exists:
        student = Student(name="Student", email="student@example.com", gpa=3.5, status="active",
                          password=generate_password_hash("student123"), role="student")
        db.session.add(student)

    financial_aid_admin_exists = Student.query.filter_by(email='fa_admin@example.com').first()
    if not financial_aid_admin_exists:
        financial_aid_admin = Student(name="Financial Aid Admin", email="fa_admin@example.com", gpa=4.0, status="active",
                                      password=generate_password_hash("faadmin123"), role="financial_aid_admin")
        db.session.add(financial_aid_admin)

    finance_department_exists = Student.query.filter_by(email='finance@example.com').first()
    if not finance_department_exists:
        finance_department = Student(name="Finance Department", email="finance@example.com", gpa=4.0, status="active",
                                     password=generate_password_hash("finance123"), role="finance_department")
        db.session.add(finance_department)

    db.session.commit()

with app.app_context():
    db.create_all()  # Ensure tables exist before adding users
    add_default_users()
# ========================== AUTHENTICATION ==========================
@app.route('/')
def login_page():
    return render_template('login.html')
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    student = Student.query.filter_by(email=email).first()

    if student and check_password_hash(student.password, password):
        session['role'] = student.role
        session['student_id'] = student.student_id

        if session['role'] == 'admin':
            return redirect(url_for('admin_home'))
        elif session['role'] == 'student':
            return redirect(url_for('student_home'))
        elif session['role'] == 'financial_aid_admin':
            return redirect(url_for('financial_aid_home'))
        elif session['role'] == 'finance_department':
            return redirect(url_for('finance_home'))
    else:
        flash("Invalid credentials. Please try again.", "danger")
        return redirect(url_for('login_page'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'role' in session:
        return redirect(url_for('student_home'))  # Redirect to home if already logged in

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        gpa = request.form['gpa']
        password = request.form['password']

        # Check if student already exists
        existing_student = Student.query.filter_by(email=email).first()
        if existing_student:
            flash("Student with this email already exists. Please log in.", "danger")
            return redirect(url_for('register'))

        # Hash the password before saving
        hashed_password = generate_password_hash(password)

        # Create new student
        new_student = Student(name=name, email=email, gpa=gpa, password=hashed_password)
        db.session.add(new_student)
        db.session.commit()

        # Automatically log in the student after registration
        session['role'] = 'student'
        session['student_id'] = new_student.student_id
        return redirect(url_for('login_page'))  # Corrected to redirect to student_home

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('role', None)
    return redirect(url_for('login_page'))
# ========================== STUDENT ROUTES ==========================

# Route for Student Dashboard (Home page)
@app.route('/student_home')
def student_home():
    if 'role' not in session or session['role'] != 'student':
        return redirect(url_for('login_page'))

    student_id = session['student_id']
    student = Student.query.get_or_404(student_id)  # Fetch student details

    scholarships = Scholarship.query.filter(Scholarship.status == 'open').all()
    return render_template('student_home.html', student=student, scholarships=scholarships)

@app.route('/profile')
def profile():
    if 'role' not in session or session['role'] != 'student':
        return redirect(url_for('login_page'))

    student_id = session['student_id']
    student = Student.query.get_or_404(student_id)

    return render_template('profile.html', student=student)

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'role' not in session or session['role'] != 'student':
        return redirect(url_for('login_page'))

    student_id = session['student_id']
    student = Student.query.get_or_404(student_id)

    current_password = request.form['current_password']
    new_password = request.form['new_password']

    if not check_password_hash(student.password, current_password):
        flash("Incorrect current password!", "danger")
        return redirect(url_for('profile'))

    student.password = generate_password_hash(new_password)
    db.session.commit()

    flash("Password updated successfully!", "success")
    return redirect(url_for('profile'))


@app.route('/student_scholarships')
def student_scholarships():
    if 'student_id' not in session:
        return redirect(url_for('login_page'))

    student_id = session['student_id']

    # Fetch all open scholarships
    scholarships = Scholarship.query.filter(Scholarship.status == 'open').all()

    # Get a list of scholarship IDs the student has already applied for
    applied_scholarships = {app.scholarship_id for app in Application.query.filter_by(student_id=student_id).all()}

    return render_template('student_scholarships.html', scholarships=scholarships,
                           applied_scholarships=applied_scholarships)

@app.route('/student/messages', methods=['GET', 'POST'])
def student_messages():
    if 'student_id' not in session:
        return redirect(url_for('login_page'))

    student_id = session['student_id']
    financial_aid_admin = Student.query.filter_by(role='financial_aid_admin').first()

    if request.method == 'POST':
        content = request.form['content']
        if content.strip():
            new_message = FA_Message(sender_id=student_id, receiver_id=financial_aid_admin.student_id, content=content)
            db.session.add(new_message)
            db.session.commit()
            flash("Message sent!", "success")

    messages = FA_Message.query.filter(
        ((FA_Message.sender_id == student_id) & (FA_Message.receiver_id == financial_aid_admin.student_id)) |
        ((FA_Message.sender_id == financial_aid_admin.student_id) & (FA_Message.receiver_id == student_id))
    ).order_by(FA_Message.timestamp).all()

    return render_template('student_fa_messages.html', messages=messages)

@app.route('/student/inbox')
def student_inbox():
    if 'role' not in session or session['role'] != 'student':
        return redirect(url_for('login_page'))

    student_id = session['student_id']
    messages = Message.query.filter_by(student_id=student_id).order_by(Message.sent_at.desc()).all()

    return render_template('student_inbox.html', messages=messages)

@app.route('/apply_scholarship/<int:scholarship_id>', methods=['POST'])
def apply_scholarship(scholarship_id):
    if 'student_id' not in session:
        flash("You need to log in first.", "danger")
        return redirect(url_for('login_page'))

    student_id = session['student_id']
    existing_application = Application.query.filter_by(student_id=student_id, scholarship_id=scholarship_id).first()

    if existing_application:
        flash("You have already applied for this scholarship.", "warning")
    else:
        new_application = Application(student_id=student_id, scholarship_id=scholarship_id, status="pending")
        db.session.add(new_application)
        db.session.commit()
        flash("Your application has been submitted.", "success")

    return redirect(url_for('student_scholarships'))  # Change this to the page where students apply


@app.route('/student/announcements')
def student_announcements():
    announcements = Announcement.query.all()  # Fetch all announcements
    return render_template('student_announcement.html', announcements=announcements)

# ========================== ADMIN ROUTES ==========================

@app.route('/admin_home')
def admin_home():
    if 'role' in session and session['role'] == 'admin':
        return render_template('admin_home.html')
    else:
        return redirect(url_for('login'))

@app.route('/admin/add_scholarship', methods=['GET', 'POST'])
def add_scholarship():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        gpa = float(request.form['gpa'])
        funds_needed = float(request.form['funds_needed'])
        new_scholarship = Scholarship(name=name, description=description, criteria_gpa=gpa, funds_needed=funds_needed)
        db.session.add(new_scholarship)
        db.session.commit()
        return redirect(url_for('add_scholarship'))

    scholarships = Scholarship.query.all()
    students = Student.query.all()
    return render_template('add_scholarships.html', scholarships=scholarships, students=students)

@app.route('/admin/delete_scholarship/<int:scholarship_id>', methods=['POST'])
def delete_scholarship(scholarship_id):
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login_page'))

    # Find the scholarship
    scholarship = Scholarship.query.get_or_404(scholarship_id)
    # Delete all applications linked to this scholarship
    Application.query.filter_by(scholarship_id=scholarship_id).delete()
    # Now delete the scholarship
    db.session.delete(scholarship)
    db.session.commit()  # Commit changes
    return redirect(url_for('add_scholarship'))

@app.route('/admin/announcement', methods=['GET', 'POST'])
def admin_announcement():
    if request.method == 'POST':
        # For posting a new announcement
        title = request.form['title']
        content = request.form['content']
        announcement = Announcement(title=title, content=content)
        db.session.add(announcement)
        db.session.commit()

    # For viewing announcements (always)
    announcements = Announcement.query.all()
    return render_template('admin_announcement.html', announcements=announcements)



@app.route('/admin/post_announcement', methods=['GET', 'POST'])
def post_announcement():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        # Create a new announcement
        announcement = Announcement(
            title=title,
            content=content,
            posted_by=session['student_id']
        )
        db.session.add(announcement)
        db.session.commit()

        flash("Announcement posted successfully.", "success")
        return redirect(url_for('post_announcement'))

    return render_template('admin_announcement.html')

@app.route('/admin/delete_announcement/<int:announcement_id>', methods=['POST'])
def delete_announcement(announcement_id):
    announcement = Announcement.query.get(announcement_id)
    if announcement:
        db.session.delete(announcement)
        db.session.commit()
    return redirect(url_for('admin_announcement'))  # Redirect back to the admin announcements page

@app.route('/admin/view_applications')
def admin_view_applications():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login_page'))

    applications = Application.query.all()
    return render_template('admin_view.html', applications=applications or [])

@app.route('/admin/view_students')
def admin_view_students():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login_page'))

    students = Student.query.filter(~Student.role.in_(['admin', 'financial_aid_admin', 'finance_department'])).all()

    return render_template('admin_change.html', students=students)

@app.route('/delete_student/<int:student_id>', methods=['POST'])
def delete_student(student_id):
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login_page'))

    student = Student.query.get_or_404(student_id)

    # Ensure the student being deleted isn't an admin
    if student.role == 'admin':
        flash("You cannot delete an admin account!", "error")
        return redirect(url_for('admin_view_students'))

    # Delete the student from the database
    db.session.delete(student)
    db.session.commit()

    flash(f"Student {student.name} has been deleted.", "success")
    return redirect(url_for('admin_view_students'))


@app.route('/admin/change_student/<int:student_id>', methods=['GET', 'POST'])
def admin_change_student(student_id):
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login_page'))

    student = Student.query.get_or_404(student_id)

    if request.method == 'POST':
        # Update GPA and password if provided
        if 'gpa' in request.form:
            student.gpa = request.form['gpa']
        if 'password' in request.form:
            student.password = generate_password_hash(request.form['password'])

        db.session.commit()
        return redirect(url_for('admin_view_students'))  # Redirect to the student list after update

    return render_template('admin_edit_student.html', student=student)

@app.route('/admin/handle_application/<int:application_id>/<action>')
def handle_application(application_id, action):
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login_page'))

    application = Application.query.get_or_404(application_id)
    student = Student.query.get(application.student_id)

    if action == 'accept':
        application.status = 'accepted'
        new_message = Message(student_id=student.student_id,
                              content=f"Your application for '{application.scholarship.name}' has been accepted.")
        db.session.add(new_message)

    elif action == 'deny':
        application.status = 'denied'
        new_message = Message(student_id=student.student_id,
                              content=f"Your application for '{application.scholarship.name}' has been denied.")
        db.session.add(new_message)

    db.session.commit()
    return redirect(url_for('admin_view_applications'))

# ========================== FINANCE DEPARTMENT AND FINANCIAL AID ADMIN ==========================
@app.route('/financial_aid_home')
def financial_aid_home():
    return render_template('financial_aid_home.html')

@app.route('/financial_aid_view_applications')
def financial_aid_view_applications():
    applications = Application.query.all()
    return render_template('financial_aid_view.html', applications=applications)

@app.route('/financial_aid/messages', methods=['GET', 'POST'])
def financial_aid_messages():
    if 'student_id' not in session or session['role'] != 'financial_aid_admin':
        return redirect(url_for('login_page'))

    admin_id = session['student_id']
    students = Student.query.filter(Student.role == 'student').all()

    selected_student_id = request.args.get('student_id', type=int)
    selected_student = Student.query.get(selected_student_id) if selected_student_id else None

    if request.method == 'POST' and selected_student:
        content = request.form['content']
        if content.strip():
            new_message = FA_Message(sender_id=admin_id, receiver_id=selected_student_id, content=content)
            db.session.add(new_message)
            db.session.commit()
            flash("Reply sent!", "success")

    messages = []
    if selected_student:
        messages = FA_Message.query.filter(
            ((FA_Message.sender_id == admin_id) & (FA_Message.receiver_id == selected_student_id)) |
            ((FA_Message.sender_id == selected_student_id) & (FA_Message.receiver_id == admin_id))
        ).order_by(FA_Message.timestamp).all()

    return render_template('fa_inbox.html', students=students, messages=messages, selected_student=selected_student)


@app.route('/financial_aid/handle_application/<int:application_id>/<action>')
def financial_aid_handle_application(application_id, action):
    if 'role' not in session or session['role'] != 'financial_aid_admin':
        return redirect(url_for('login_page'))

    application = Application.query.get_or_404(application_id)
    student = Student.query.get(application.student_id)

    if action == 'accept':
        application.status = 'accepted'
        new_message = Message(student_id=student.student_id,
                              content=f"Your application for '{application.scholarship.name}' has been accepted.")
        db.session.add(new_message)

    elif action == 'deny':
        application.status = 'denied'
        new_message = Message(student_id=student.student_id,
                              content=f"Your application for '{application.scholarship.name}' has been denied.")
        db.session.add(new_message)

    db.session.commit()
    return redirect(url_for('financial_aid_view_applications'))


@app.route('/financial_aid_allocate')
def financial_aid_allocate():
    if 'role' not in session or session['role'] not in ['financial_aid_admin', 'finance_department']:
        return redirect(url_for('login_page'))

    applications = Application.query.filter_by(status='accepted').all()

    is_financial_aid_admin = session['role'] == 'financial_aid_admin'

    return render_template('financial_aid_allocate.html', applications=applications,is_financial_aid_admin=is_financial_aid_admin)

@app.route('/allocate_funds/<int:application_id>', methods=['POST'])
def allocate_funds(application_id):
    if 'role' not in session or session['role'] != 'financial_aid_admin':
        return redirect(url_for('login_page'))

    application = Application.query.get_or_404(application_id)
    allocated_funds = float(request.form['allocated_funds'])

    # Calculate how much this student has already received
    total_allocated_to_student = sum(
        allocation.amount_allocated for allocation in application.student.fund_allocations
        if allocation.scholarship_id == application.scholarship_id
    )

    # Calculate remaining funds the student can receive for this scholarship
    remaining_needed_for_student = application.scholarship.funds_needed - total_allocated_to_student

    if allocated_funds > remaining_needed_for_student:
        flash("Allocated funds cannot exceed the student's remaining required funds.", "error")
        return redirect(url_for('financial_aid_allocate'))

    # Fetch available funds from the database
    available_funds = AvailableFunds.query.first()
    if not available_funds:
        available_funds = AvailableFunds(amount=0)  # Initialize if not present
        db.session.add(available_funds)
        db.session.commit()

    # Check if there are sufficient funds
    if available_funds.amount >= allocated_funds:
        # Create a new fund allocation record for the student
        allocation = FundAllocation(
            student_id=application.student_id,
            scholarship_id=application.scholarship_id,
            amount_allocated=allocated_funds,
            allocated_by=session['student_id']  # Financial aid admin's ID
        )
        db.session.add(allocation)

        # Update the total funds allocated for the scholarship
        application.scholarship.funds_allocated += allocated_funds

        # Deduct the allocated funds from the available funds
        available_funds.amount -= allocated_funds

        # Commit changes
        db.session.commit()

        flash(f"Allocated RM{allocated_funds} for {application.student.name}'s scholarship.", "success")
    else:
        flash("Insufficient available funds.", "error")

    return redirect(url_for('financial_aid_allocate'))

@app.route('/finance_home')
def finance_home():
    return render_template('finance_home.html')


@app.route('/track_funds', methods=['GET', 'POST'])
def track_funds():
    if 'role' not in session or session['role'] != 'finance_department':
        return redirect(url_for('login_page'))

    # Handle POST request to set available funds
    if request.method == 'POST':
        available_funds = float(request.form['available_funds'])

        # Store the available funds in the database (persistent)
        current_funds = AvailableFunds.query.first()
        if current_funds:
            current_funds.amount = available_funds  # Update existing record
        else:
            new_fund = AvailableFunds(amount=available_funds)  # Create a new record if no existing one
            db.session.add(new_fund)

        db.session.commit()
        flash(f"Available funds set to RM{available_funds}", 'success')

    available_funds = AvailableFunds.query.first()  # Fetch the available funds from the database
    available_funds_amount = available_funds.amount if available_funds else 0.00  # Default to 0 if not set

    # Fetch fund allocation records
    fund_allocations = FundAllocation.query.all()

    return render_template('track_funds.html', available_funds=available_funds_amount,
                           fund_allocations=fund_allocations)


@app.route('/set_available_funds', methods=['POST'])
def set_available_funds():
    if 'role' not in session or session['role'] != 'finance_department':
        return redirect(url_for('login_page'))

    available_funds = float(request.form['available_funds'])
    session['available_funds'] = available_funds  # Store in session for now

    flash(f"Available funds updated to RM{available_funds}", 'success')
    return redirect(url_for('track_funds'))

@app.route('/download_financial_report')
def download_financial_report():
    # Fetch fund allocation data
    fund_allocations = FundAllocation.query.all()

    # Create a CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Student Name', 'Scholarship', 'Amount Allocated', 'Date Allocated'])

    # Write the data for each fund allocation
    for allocation in fund_allocations:
        writer.writerow([
            allocation.student.name,
            allocation.scholarship.name,
            allocation.amount_allocated,
            allocation.allocated_at  # Using the allocated_at field
        ])

    output.seek(0)  # Go back to the start of the file

    # Serve the file as a download
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=financial_report.csv'}
    )

# ========================== RUN APP ==========================

if __name__ == '__main__':
    app.run(debug=True)
