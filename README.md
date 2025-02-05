# Abnormalities Detection in Endpoints using AI

**Abnormal_log-Detection** is an AI-driven application designed to detect anomalies in endpoint logs, enhancing system monitoring and security.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Contributing](#contributing)


## Introduction

Monitoring endpoint logs is crucial for identifying potential security threats and system malfunctions. **Abnormal_log-Detection** leverages artificial intelligence to automatically detect unusual patterns in these logs, facilitating proactive system management.

## Features

- **AI-Powered Analysis**: Utilizes machine learning algorithms to analyze log data.
- **Real-Time Monitoring**: Provides immediate detection of anomalies as they occur.
- **User-Friendly Interface**: Offers a clear and intuitive interface for monitoring and analysis.

## Installation

To set up **Abnormal_log-Detection** on your local machine, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Deeku-01/Abnormal_log-Detecction.git
   ```
   ```bash
   cd Abnormal_log-Detecction
   ```

2. **Install Dependencies**:
   Ensure you have [Python 3.x](https://www.python.org/downloads/) installed. Then, install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To start the application:

```bash
python app.py
```

This will launch the web interface for monitoring and analyzing endpoint logs.

## Project Structure

- `app.py`: The main application script that runs the web server.
- `anomaly_detector.py`: Contains the AI model and logic for detecting anomalies in logs.
- `anomaly_model.pkl`: Pre-trained machine learning model for anomaly detection.
- `scaler.pkl`: Pre-fitted scaler for data normalization.
- `request_simulator.py`: Simulates log requests for testing purposes.
- `templates/`: Directory containing HTML templates for the web interface.
- `static/css/`: Directory containing CSS files for styling the web interface.

## Contributing

We welcome contributions to enhance **Abnormal_log-Detection**. To contribute:

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature/YourFeatureName
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add your feature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature/YourFeatureName
   ```
5. Open a Pull Request detailing your changes.

