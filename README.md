# sec-org-app
University of Aveiro. Project in Security Information and Organization, groups of 4.

# Purpose
The purpose of this project was to write two versions of the same Health Services Application - with and without vulnerabilities. Attack vector analysis allowed the project team to identify and assess 6 CWEs and remove them in the updated version of the application.

# Key takeaways
It is important to take security aspects into consideration during the team's software development lifecycle.

# authors
 - 112169 MIRON OSKROBA
 - 112018 ZUZANNA SIKORSKA
 - 112282 JANNIS JAKOB MALENDE
 - 112059 STANISLAW FRANCZYK

## project description
Our application offers the following services:
- registration of users
- login and logout of users
- make an appointment
- doctor simulator (automatic diagnosis)
- view diagnosis issued automatically by doctor simulator
- contact form to contact the clinic

### vulnerabilities
 - CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
 - CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
 - CWE-1104 Use of Unmaintained Third Party Components
 - CWE-522 Insufficiently Protected Credentials
 - CWE-259 Use of Hard-coded Password
 - CWE-532 Insertion of Sensitive Information into Log File
 
 ![Alt text](/readme-photos/vulnerabilities-summary.png?raw=true "scores")
