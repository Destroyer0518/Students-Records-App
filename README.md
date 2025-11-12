# Student Attendance & Exam Records App

A Streamlit app using MongoDB to manage student attendance and exam marks.

## Run Locally
1. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
2. Add `.streamlit/secrets.toml` file with your MongoDB credentials:

   ```toml
   [mongo]
   uri = "your_mongodb_connection_uri"
   db = "school_db"
   ```

3. Run the app
   ```bash
   streamlit run streamlit_students_attendance_exam_app.py
   ```

## Deploy on Streamlit Cloud
1. Push this folder to a GitHub repo.
2. On [Streamlit Cloud](https://share.streamlit.io), create a new app and connect this repo.
3. Add your secrets in app settings as shown above.
