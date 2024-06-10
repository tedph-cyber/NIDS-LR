import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, conf
import tensorflow as tf
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

# Load the pre-trained model
model = load_model('model.h5', compile=False)

# Define the loss function and compile the model manually
loss_fn = tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True, reduction=tf.keras.losses.Reduction.SUM_OVER_BATCH_SIZE)
model.compile(optimizer='adam', loss=loss_fn, metrics=['accuracy'])

# Load the .pcap file
packets = rdpcap('dummy_traffic.pcap')

# Function to extract features from packets
def extract_features(packet):
    features = {}
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP] if packet.haslayer(TCP) else None

        # Example features - add more based on your model's training
        features['protocol'] = ip_layer.proto
        features['length'] = len(packet)
        features['src'] = ip_layer.src
        features['dst'] = ip_layer.dst
        if tcp_layer:
            features['sport'] = tcp_layer.sport
            features['dport'] = tcp_layer.dport
            features['flags'] = int(tcp_layer.flags)  # Convert FlagValue to int
        else:
            features['sport'] = 0
            features['dport'] = 0
            features['flags'] = 0
    return features

# Extract features from packets
captured_packets = []
for packet in packets:
    features = extract_features(packet)
    captured_packets.append(features)

# Convert captured packets to DataFrame
df = pd.DataFrame(captured_packets)

# Ensure all required features are present, fill missing values
required_features = ['protocol', 'length', 'src', 'dst', 'sport', 'dport', 'flags']  # Add all features used during training
for feature in required_features:
    if feature not in df.columns:
        df[feature] = 0

# Preprocess data
X = df[required_features].values

# Convert categorical data to numerical if needed (e.g., IP addresses)
df['src'] = df['src'].apply(lambda x: int(''.join([format(int(octet), '08b') for octet in x.split('.')]), 2) if isinstance(x, str) else 0)
df['dst'] = df['dst'].apply(lambda x: int(''.join([format(int(octet), '08b') for octet in x.split('.')]), 2) if isinstance(x, str) else 0)

# Scale the data
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Run the model
predictions = model.predict(X_scaled)
predicted_classes = np.argmax(predictions, axis=1)

# Assuming you have the ground truth labels for the traffic
# Replace 'true_labels' with your actual labels
true_labels = [...]  # Replace with your true labels

# Calculate metrics
cm = confusion_matrix(true_labels, predicted_classes)
accuracy = accuracy_score(true_labels, predicted_classes)
precision = precision_score(true_labels, predicted_classes, average='macro')
recall = recall_score(true_labels, predicted_classes, average='macro')
f1 = f1_score(true_labels, predicted_classes, average='macro')

# Detection Rate (DR)
TP = cm[1, 1]
FN = cm[1, 0]
detection_rate = TP / (TP + FN)

# False Positive Rate (FPR)
FP = cm[0, 1]
TN = cm[0, 0]
false_positive_rate = FP / (FP + TN)

# False Alarm Rate (FAR)
# Assuming you measure this per unit time, for now, we use the raw false positive count
false_alarm_rate = FP

# Latency
# You might need to measure the time taken to process packets
# This is a simplified example to show latency calculation
import time
start_time = time.time()
model.predict(X_scaled)
latency = time.time() - start_time

# Computational Efficiency
import psutil
process = psutil.Process()
cpu_usage = process.cpu_percent(interval=1)
memory_usage = process.memory_info().rss  # in bytes

# Print metrics
print(f"Detection Rate (DR): {detection_rate}")
print(f"False Positive Rate (FPR): {false_positive_rate}")
print(f"Accuracy: {accuracy}")
print(f"Precision: {precision}")
print(f"Recall: {recall}")
print(f"F1-score: {f1}")
print(f"False Alarm Rate (FAR): {false_alarm_rate}")
print(f"Latency: {latency} seconds")
print(f"CPU Usage: {cpu_usage}%")
print(f"Memory Usage: {memory_usage / (1024 ** 2)} MB")
