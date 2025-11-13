import streamlit as st
from pymongo import MongoClient
from datetime import datetime
import pandas as pd
import bcrypt
import toml
import os
from bson.objectid import ObjectId

# ---------------------------
# Configuration / DB Connect
# ---------------------------

@st.cache_resource
def get_db():
    uri, dbname = None, None

    # --- Try Streamlit secrets first, safely ---
    try:
        if "mongo" in st.secrets:
            uri = st.secrets["mongo"]["uri"]
            dbname = st.secrets["mongo"]["db"]
    except Exception:
        pass  # No Streamlit secrets found, continue to fallback

    # --- Fallback: check Render Secret Files (/etc/secrets/secrets.toml) ---
    if not uri:
        secret_path = "/etc/secrets/secrets.toml"
        if os.path.exists(secret_path):
            secrets = toml.load(secret_path)
            uri = secrets["mongo"]["uri"]
            dbname = secrets["mongo"]["db"]
        else:
            st.error("❌ No secrets found. Please add `secrets.toml` in Render Secret Files.")
            st.stop()

    # --- Connect to MongoDB ---
    try:
        client = MongoClient(uri)
        db = client[dbname]
        client.admin.command("ping")  # test connection
        st.sidebar.success("✅ Connected to MongoDB")
        return db
    except Exception as e:
        st.sidebar.error(f"❌ Failed to connect to MongoDB: {e}")
        st.stop()

db = get_db()
users_col = db.users
students_col = db.students
attendance_col = db.attendance
exams_col = db.exams


# ---------------------------
# Utilities
# ---------------------------

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except Exception:
        return False

def create_user(username, password, role="user"):
    if users_col.find_one({"username": username}):
        return False, "Username already exists"
    hashed = hash_password(password)
    users_col.insert_one({
        "username": username,
        "password": hashed,
        "role": role,
        "created_at": datetime.utcnow()
    })
    return True, "User created"

def authenticate(username, password):
    user = users_col.find_one({"username": username})
    if not user:
        return False, None
    if verify_password(password, user["password"]):
        return True, {"_id": str(user["_id"]), "username": user["username"], "role": user.get("role", "user")}
    return False, None


# ---------------------------
# Create initial admin if none exists
# ---------------------------
if users_col.count_documents({"role": "admin"}) == 0:
    if not users_col.find_one({"username": "admin"}):
        users_col.insert_one({
            "username": "admin",
            "password": hash_password("admin123"),
            "role": "admin",
            "created_at": datetime.utcnow()
        })


# ---------------------------
# Session state helpers
# ---------------------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "user_info" not in st.session_state:
    st.session_state["user_info"] = None


# ---------------------------
# UI: Login Page
# ---------------------------

def login_page():
    st.title("🎓 Students Attendance & Exam Records")
    st.subheader("Login Portal")
    role_choice = st.radio("Login as", ("user", "admin"))
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("Login"):
            ok, info = authenticate(username, password)
            if ok:
                if info["role"] != role_choice:
                    st.error(f"User is not registered as {role_choice}")
                else:
                    st.session_state["logged_in"] = True
                    st.session_state["user_info"] = info
                    st.success(f"Logged in as {info['username']} ({info['role']})")
                    st.rerun()
            else:
                st.error("Invalid credentials")
    with col2:
        if st.button("Sign up as user"):
            if not username or not password:
                st.error("Provide username and password to sign up")
            else:
                ok, msg = create_user(username, password, role="user")
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)


# ---------------------------
# Admin Page
# ---------------------------

def admin_page(user_info):
    st.title("🛠️ Admin Dashboard")
    st.write(f"Signed in as: {user_info['username']}")

    st.header("Create New User")
    with st.form("create_user_form"):
        new_username = st.text_input("New username")
        new_password = st.text_input("New password", type="password")
        new_role = st.selectbox("Role", ("user", "admin"))
        submitted = st.form_submit_button("Create user")
        if submitted:
            if not new_username or not new_password:
                st.error("Both username and password are required")
            else:
                ok, msg = create_user(new_username, new_password, new_role)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

    st.header("Existing users")
    users = list(users_col.find({}, {"password": 0}))
    if users:
        df = pd.DataFrame(users)
        df["_id"] = df["_id"].astype(str)
        st.dataframe(df)
    else:
        st.info("No users yet")

    if st.button("Logout"):
        st.session_state["logged_in"] = False
        st.session_state["user_info"] = None
        st.rerun()


# ---------------------------
# User Page
# ---------------------------

def user_page(user_info):
    st.sidebar.title("Navigation")
    menu = st.sidebar.radio("Go to", ["Students", "Attendance", "Exams", "Report Card", "Export / Tools", "Logout"])

    st.title("👩‍🎓 User Dashboard")
    st.write(f"Logged in as: {user_info['username']}")

    if menu == "Students":
        st.header("Manage Students")
        with st.form("add_student"):
            name = st.text_input("Student Name")
            roll = st.text_input("Roll / ID")
            klass = st.text_input("Class / Grade")
            submit = st.form_submit_button("Add / Update Student")
            if submit:
                if not name or not roll:
                    st.error("Name and Roll ID required")
                else:
                    students_col.update_one(
                        {"roll": roll},
                        {"$set": {"name": name, "class": klass, "updated_at": datetime.utcnow()}},
                        upsert=True
                    )
                    st.success("Student saved")

        st.subheader("All Students")
        students = list(students_col.find())
        if students:
            df = pd.DataFrame(students)
            df["_id"] = df["_id"].astype(str)
            st.dataframe(df)
        else:
            st.info("No students yet")

    elif menu == "Attendance":
        st.header("Record Attendance")
        students = list(students_col.find())
        if not students:
            st.info("Please add students first")
        else:
            df_students = pd.DataFrame(students)
            selected = st.multiselect("Select student rolls to mark present", df_students["roll"].tolist())
            date = st.date_input("Attendance Date", datetime.today())
            submit = st.button("Save Attendance")
            if submit:
                for roll in selected:
                    attendance_col.update_one(
                        {"roll": roll, "date": date.isoformat()},
                        {"$set": {"present": True, "updated_by": user_info['username'], "timestamp": datetime.utcnow()}},
                        upsert=True
                    )
                st.success(f"Saved attendance for {len(selected)} students on {date}")

        st.subheader("View Attendance")
        with st.form("view_attendance"):
            v_roll = st.text_input("Roll (leave blank for all)")
            v_from = st.date_input("From", datetime.today())
            v_to = st.date_input("To", datetime.today())
            v_submit = st.form_submit_button("View")
            if v_submit:
                query = {"date": {"$gte": v_from.isoformat(), "$lte": v_to.isoformat()}}
                if v_roll:
                    query["roll"] = v_roll
                rows = list(attendance_col.find(query))
                if rows:
                    df = pd.DataFrame(rows)
                    df["_id"] = df["_id"].astype(str)
                    st.dataframe(df)
                else:
                    st.info("No attendance records found")

    elif menu == "Exams":
        st.header("Enter Exam Marks")
        students = list(students_col.find())
        student_rolls = [s["roll"] for s in students]
        with st.form("add_marks"):
            roll = st.selectbox("Student Roll", student_rolls)
            subject = st.text_input("Subject")
            marks = st.number_input("Marks", min_value=0, max_value=100)
            exam_date = st.date_input("Exam Date", datetime.today())
            submitted = st.form_submit_button("Save Marks")
            if submitted:
                exams_col.insert_one({
                    "roll": roll,
                    "subject": subject,
                    "marks": float(marks),
                    "date": exam_date.isoformat(),
                    "entered_by": user_info['username'],
                    "timestamp": datetime.utcnow()
                })
                st.success("Marks saved")

        st.subheader("All Exam Records")
        rows = list(exams_col.find())
        if rows:
            df = pd.DataFrame(rows)
            df["_id"] = df["_id"].astype(str)
            st.dataframe(df)
        else:
            st.info("No exam records yet")

    elif menu == "Report Card":
        st.header("Generate Report Card")
        students = list(students_col.find())
        if not students:
            st.info("Add students first")
        else:
            roll = st.selectbox("Select Student", [s["roll"] for s in students])
            if st.button("Generate Report Card"):
                student = students_col.find_one({"roll": roll})
                exams = list(exams_col.find({"roll": roll}))
                if not exams:
                    st.info("No exam records for this student")
                else:
                    df = pd.DataFrame(exams)
                    avg = df["marks"].mean()
                    st.subheader(f"Report Card for {student.get('name', roll)}")
                    st.write(df[["subject", "marks", "date"]])
                    st.markdown(f"**Average Marks:** {avg:.2f}")

    elif menu == "Export / Tools":
        st.header("Export Data")
        if st.button("Export Students CSV"):
            rows = list(students_col.find())
            if rows:
                df = pd.DataFrame(rows)
                csv = df.to_csv(index=False)
                st.download_button("Download students.csv", csv, file_name="students.csv")
            else:
                st.info("No students to export")
        if st.button("Export Exams CSV"):
            rows = list(exams_col.find())
            if rows:
                df = pd.DataFrame(rows)
                csv = df.to_csv(index=False)
                st.download_button("Download exams.csv", csv, file_name="exams.csv")
            else:
                st.info("No exams to export")

    elif menu == "Logout":
        st.session_state["logged_in"] = False
        st.session_state["user_info"] = None
        st.rerun()


# ---------------------------
# Main
# ---------------------------

def main():
    if not st.session_state["logged_in"]:
        login_page()
    else:
        info = st.session_state["user_info"]
        if info["role"] == "admin":
            admin_page(info)
        else:
            user_page(info)

if __name__ == "__main__":
    main()                                                      
