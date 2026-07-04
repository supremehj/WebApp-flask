from flask import Flask, render_template, request, jsonify
from werkzeug.exceptions import RequestEntityTooLarge
import joblib
import os
import pandas as pd
from pyaxmlparser import APK
#from androguard.core.apk import APK
from werkzeug.utils import secure_filename
from gevent.pywsgi import WSGIServer
from datetime import datetime
import collections
import json

app = Flask(__name__)

# Load the pre-trained Random Forest model
model_path = 'random_forest_model_top45.pkl'
rf_classifier = joblib.load(model_path)

# Define the upload and output folders
upload_folder = 'uploads'
output_folder = 'output'
app.config['UPLOAD_FOLDER'] = upload_folder
app.config['OUTPUT_FOLDER'] = output_folder

# Set a limit for the maximum allowed file size 
app.config['MAX_CONTENT_LENGTH'] = 700 * 1024 * 1024

# Define the features to check for
features_list = ['attachInterface', 'android.intent.action.SEND_MULTIPLE', 'getBinder',
       'NFC', 'READ_PHONE_STATE', 'getCallingUid', 'BLUETOOTH',
       'ServiceConnection', 'GET_ACCOUNTS', 'PackageInstaller', 'CAMERA',
       'getCallingPid', 'android.intent.action.BOOT_COMPLETED', 'transact',
       'android.content.pm.Signature', 'UPDATE_DEVICE_STATS',
       'onServiceConnected', 'bindService', 'SEND_SMS', 'Context.bindService',
       'android.intent.action.SCREEN_OFF', 'ACCESS_WIFI_STATE',
       'DexClassLoader', 'android.intent.action.ACTION_POWER_DISCONNECTED',
       'STATUS_BAR', 'VIBRATE', 'android.intent.action.TIMEZONE_CHANGED',
       'HttpUriRequest', 'ProcessBuilder', 'READ_EXTERNAL_STORAGE',
       'android.intent.action.TIME_SET', 'RECORD_AUDIO', 'System.loadLibrary',
       'Runtime.getRuntime', 'android.intent.action.ACTION_POWER_CONNECTED',
       'android.os.Binder', 'SecretKey', 'RECEIVE_BOOT_COMPLETED',
       'android.intent.action.SEND', 'KeySpec', '/system/bin', 'onBind',
       'INSTALL_PACKAGES', 'ClassLoader', 'android.intent.action.SENDTO']

def extract_features_from_apk(apk_file_path):
    try:
        a = APK(apk_file_path)
        permissions = a.get_permissions()

        # Initialize all features to 0
        feature_present = {feature: 0 for feature in features_list}

        # Update feature_present based on extracted permissions
        for permission in permissions:
            # Extract the last part of the permission name after the last dot
            feature_name = permission.split('.')[-1]
            if feature_name in feature_present:
                feature_present[feature_name] = 1

        # Save extracted features to Excel
        output_excel_path = os.path.join(app.config['OUTPUT_FOLDER'], 'Android_Permissions.xlsx')
        save_features_to_excel(feature_present, output_excel_path)

        return feature_present, permissions
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None,[]

def save_features_to_excel(features, excel_file_path, num_cols=45):
    try:
        if len(features) != num_cols:
            print("Warning: The number of features does not match the expected number of columns")
            return

        # Create a DataFrame with two rows: one for feature names, one for their values
        df = pd.DataFrame([list(features.keys()), list(features.values())])

        # Ensure the DataFrame has exactly 45 columns
        if df.shape[1] != num_cols:
            print("Warning: The number of columns in DataFrame is not 45")
            return

        df.to_excel(excel_file_path, header=False, index=False)
        print(f"Features saved to {excel_file_path}")
    except Exception as e:
        print(f"Error saving to Excel: {e}")

def predict_malware(features):
    try:
        input_data = pd.DataFrame([features.values()], columns=features.keys())
        prediction = rf_classifier.predict(input_data)
        return prediction[0]
    except Exception as e:
        print(f"Error predicting malware: {e}")
        return None
    
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file_error(e):
    # Render an error page with a friendly message
    return render_template('error.html', message="The uploaded file is too large. Please upload a file less than 700 MB."), 413

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/detect_malware', methods=['POST'])
def detect_malware():
    if 'file' not in request.files:
        return render_template('index.html', error="No file part")

    apk_file = request.files['file']

    if apk_file.filename == '':
        return render_template('index.html', error="No selected file")

    # Check if the file is an APK file
    if not apk_file.filename.endswith('.apk'):
        return render_template('index.html', error="Please upload only an APK file")

    # Secure the filename and save the file to the upload folder
    if apk_file:
        filename = secure_filename(apk_file.filename)
        apk_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        apk_file.save(apk_path)

        # Extract features and predict malware
        features, extracted_permissions = extract_features_from_apk(apk_path)
        
        if features is not None:
            prediction = predict_malware(features)
        else:
            return render_template('index.html', error="Error extracting features from APK")

        if prediction is not None:
            readable_prediction = "Malware" if prediction == 'S' else "Benign"
            # Set the additional details
            upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            apk_name = filename  # The name of the uploaded APK file
            # Count the occurrences of each permission
            permission_counts = collections.Counter(extracted_permissions)
            permissions = list(permission_counts.keys())
            counts = list(permission_counts.values())
            
            # Debugging
            print("Permissions:", permissions)
            print("Counts:", counts)
            
            malware_status_message = "Based on these permissions, the file is classified as " + readable_prediction

            return render_template('result.html', 
                                   result=readable_prediction,
                                   upload_time=upload_time, 
                                   apk_name=apk_name, 
                                   permissions=permissions,  # Send as list, not JSON
                                   permission_counts=counts,  # Send as list, not JSON
                                   permissions_count=len(permissions),
                                   malware_status_message=malware_status_message)
        
    return render_template('index.html', error="Invalid file or error in processing")

@app.route('/debug')
def debug():
    import os
    static_files = os.listdir('static') if os.path.exists('static') else []
    templates_files = os.listdir('templates') if os.path.exists('templates') else []
    return f"Static files: {static_files}<br>Templates: {templates_files}"

if __name__ == '__main__':
    # Get port from environment variable for Render
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
