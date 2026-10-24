# Network Forensic Tool for Attack Analysis

## 1. Project Overview
The Network Forensic Tool for Attack Analysis is a Python-based application that analyzes network packet capture files (PCAP) to identify suspicious network activity and organize packet evidence for investigation.

## 2. Objectives
- Analyze network packets from PCAP files.
- Detect suspicious traffic using predefined detection rules.
- Identify possible port scans and suspicious TCP SYN patterns.
- Maintain forensic evidence and timelines.
- Store analysis results in MongoDB.
- Generate downloadable JSON and PDF reports.

## 3. Technologies Used
- Python
- Flask
- Scapy
- MongoDB
- HTML, CSS and JavaScript
- ReportLab for PDF generation

## 4. Main Modules
- **Frontend:** Uploads PCAP files and displays analysis results.
- **Backend:** Handles uploads and coordinates analysis.
- **Detection Engine:** Checks packets against predefined detection rules.
- **Forensic Module:** Organizes packet evidence and timelines.
- **Database Module:** Saves analysis results in MongoDB.
- **Report Module:** Generates downloadable PDF reports.

## 5. How to Run
1. Install Python and MongoDB.
2. Open PowerShell in the project directory.
3. Install the dependencies using `py -m pip install -r requirements.txt`.
4. Start MongoDB.
5. Run the application using `py backend\app.py`.
6. Open the dashboard using the configured local frontend address.
7. Upload a supported `.pcap` or `.pcapng` file and analyze it.
8. Download the JSON or PDF report.

## 6. Test Cases
- Normal sample traffic: checks whether ordinary sample traffic is processed.
- Synthetic port-scan traffic: checks the port-scan detection rule.
- Synthetic TCP SYN traffic: checks the configured SYN-pattern detection rule.
- Invalid file type: checks upload validation.

## 7. Outputs
- Attack detection report in JSON format.
- Forensic timeline in JSON format.
- Downloadable PDF analysis report.
- Analysis results stored in MongoDB.

## 8. Limitations
The tool uses predefined rules, so it may not detect every type of network attack. Alerts require further investigation and should not be treated as definitive proof of an attack. Test results depend on the supplied packet capture and detection rules.

## 9. Future Enhancements
- Add more detection rules.
- Improve report visualization.
- Add filtering and searching for forensic records.
- Improve detection accuracy using additional analysis methods.
