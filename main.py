import pandas as pd
import numpy as np
from scapy.all import sniff, IP
import tensorflow as tf
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler

# Load the pre-trained model without compiling it
model = load_model('model.h5', compile=False)

# Define the loss function and compile the model manually
loss_fn = tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True, reduction=tf.keras.losses.Reduction.SUM_OVER_BATCH_SIZE)
model.compile(optimizer='adam', loss=loss_fn, metrics=['accuracy'])

# Define a packet handler
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        # Extract features
        features = {
            'protocol': ip_layer.proto,
            'length': len(packet)
        }
        return features

# Capture packets
captured_packets = []

def start_sniffing(interface='eth0', count=100):
    sniff(iface=interface, prn=lambda x: captured_packets.append(packet_handler(x)), count=count)

# Start capturing packets
start_sniffing(interface='192.168.158.73', count=100)

# Convert captured packets to DataFrame
df = pd.DataFrame(captured_packets)

# Preprocess data
features = ['protocol', 'length']
X = df[features].values
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Run the model
predictions = model.predict(X_scaled)
predicted_classes = np.argmax(predictions, axis=1)

# Add predictions to DataFrame
df['predicted_class'] = predicted_classes

# Display results
print(df)

# Monitor and alert
for index, row in df.iterrows():
    if row['predicted_class'] == 1:  # Assuming '1' indicates an anomaly
        print(f"Anomaly detected: {row}")
