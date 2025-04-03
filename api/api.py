from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
import numpy as np
import joblib
from datetime import datetime, timedelta
import subprocess
import threading
import time
from collections import defaultdict
import os
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)
CORS(app)
model = joblib.load('./model.joblib')

# Structures de données
blacklist = {}
request_counter = defaultdict(int)
stats = {
    'total': 0,
    'malicious': 0,
    'normal': 0,
    'incoming': 0,
    'outgoing': 0,
    'last_updated': datetime.now().isoformat()
}

# Locks pour thread-safety
data_lock = threading.Lock()
blacklist_lock = threading.Lock()


def process_pcap():
    while True:
        try:
            print("Lancement de tshark pour traiter capture.pcap...")
            result = subprocess.run([
                'tshark', '-r', '../captures/capture.pcap',
                '-T', 'fields',
                '-E', 'header=y',
                '-E', 'separator=,',
                '-E', 'quote=d',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.srcport',
                '-e', 'tcp.dstport',
                '-e', 'http.request.method',
                '-e', 'tcp.flags',
                '-e', 'frame.len'
            ], stdout=open('../captures/network_data.csv', 'w'), check=True, text=True)
            
            print("tshark terminé avec succès.")
            if os.path.exists('../captures/network_data.csv'):
                with open('../captures/network_data.csv', 'r') as f:
                    content = f.read().strip()
                    if not content:
                        print("Erreur : network_data.csv est complètement vide.")
                    elif content.count('\n') <= 1:
                        print("Erreur : network_data.csv ne contient que l'en-tête.")
                    else:
                        print("network_data.csv généré avec succès. Nombre de lignes estimées:", content.count('\n'))
            else:
                print("Erreur : network_data.csv n'a pas été créé.")
            
            analyze_traffic()
            time.sleep(30)
            
        except subprocess.CalledProcessError as e:
            print(f"Erreur lors de l'exécution de tshark : {e}")
        except Exception as e:
            print(f"Error processing pcap: {e}")  


def analyze_traffic():
    global stats
    try:
        df = pd.read_csv('../captures/network_data.csv', on_bad_lines='skip', quotechar='"')
        
        if df.empty:
            print("Erreur : Le fichier network_data.csv est vide ou n'a pas été lu correctement.")
            return
        
        print("Colonnes disponibles:", df.columns)
        print("Colonnes attendues par le modèle:", model.feature_names_in_)
        
        victim_ip = '20.0.0.2'
        
        
        with data_lock:
            df = df[df['ip.src'] != victim_ip].copy()
            # print(f"Colonnes disponibles: {df.columns}")
            stats['total'] = int(len(df))  # Conversion en int natif
            stats['incoming'] = int(len(df[df['ip.dst'] == '20.0.0.2']))
            stats['outgoing'] = int(len(df[df['ip.src'] == '20.0.0.2']))
            
            df_transformed = pd.DataFrame()
            
            # Transformation des données
            df_transformed['duration'] = 0
            df_transformed['protocol_type'] = df['tcp.srcport'].apply(
                lambda x: 'tcp' if pd.notna(x) else 'udp'
            )
            df_transformed['service'] = df['tcp.dstport'].apply(
                lambda x: 'ssh' if pd.to_numeric(x, errors='coerce') == 22 else 'http' if pd.to_numeric(x, errors='coerce') == 80 else 'other'
            )
            df_transformed['flag'] = df['tcp.flags'].fillna('0x00')
            df_transformed['src_bytes'] = df['frame.len']
            df_transformed['dst_bytes'] = df['frame.len']
            df_transformed['land'] = (df['ip.src'] == df['ip.dst']).astype(int)
            df_transformed['wrong_fragment'] = 0
            df_transformed['urgent'] = df['tcp.flags'].apply(
                lambda x: 1 if 'U' in str(x) else 0
            )
            df_transformed['hot'] = df['ip.src'].map(df['ip.src'].value_counts())
            
            # Encodage catégorique
            le_protocol = LabelEncoder().fit(['tcp', 'udp', 'icmp'])
            le_service = LabelEncoder().fit(['http', 'ssh', 'other'])
            le_flag = LabelEncoder().fit(df_transformed['flag'].unique())
            
            df_transformed['protocol_type'] = le_protocol.transform(df_transformed['protocol_type'])
            df_transformed['service'] = le_service.transform(df_transformed['service'])
            df_transformed['flag'] = le_flag.transform(df_transformed['flag'])
            
            print("Nombre de lignes dans df_transformed:", len(df_transformed))
            if df_transformed.empty:
                print("Erreur : df_transformed est vide après transformation.")
                return
            
            # Prédiction avec le modèle
            features = [col for col in model.feature_names_in_ if col in df_transformed.columns]
            
            # print(df_transformed[features])
            predictions = model.predict(df_transformed[features])
            df['prediction'] = predictions
            
            # Mise à jour des stats
            stats['malicious'] = int(sum(predictions == 'anomaly'))  # Conversion en int natif
            stats['normal'] = int(sum(predictions == 'normal'))      # Conversion en int natif
            stats['last_updated'] = datetime.now().isoformat()
            
            print(f"Prédictions - Malveillant: {stats['malicious']}, Normal: {stats['normal']}")
            
            update_blacklist(df)

    except Exception as e:
        print(f"Analysis error: {e}")


def update_blacklist(df):
    global blacklist
    with blacklist_lock:
        malicious_df = df[df['prediction'] == 'anomaly']
        malicious_ips = malicious_df[malicious_df['tcp.dstport'].isin([22, 80, 443, 3389])]['ip.src'].value_counts()
        current_time = datetime.now()
        victim_ip = '20.0.0.2'
        internal_ip = '20.0.0.3'  # Ignorer machine_interne
        for ip, count in malicious_ips.items():
            if count >= 10 and ip != victim_ip and ip != internal_ip:
                blacklist[ip] = {
                    'timestamp': current_time.isoformat(),
                    'expires': (current_time + timedelta(minutes=5)).isoformat(),
                    'reason': 'Multiple malicious attempts'
                }
                print(f"Ajouté {ip} à blacklist avec {count} paquets")
        print(f"IPs malveillantes détectées avec leur compte : {malicious_ips.to_dict()}")
        
# def update_blacklist(df):
#     global blacklist
#     with blacklist_lock:
#         # Filtrer les paquets malveillants
#         malicious_df = df[df['prediction'] == 'anomaly']
#         # Compter les IPs sources qui initient des connexions suspectes
#         malicious_ips = malicious_df[malicious_df['tcp.dstport'].isin([22, 80, 443, 3389])]['ip.src'].value_counts()
#         current_time = datetime.now()
#         victim_ip = '20.0.0.2'  # IP connue de hote_principal
#         for ip, count in malicious_ips.items():
#             if count >= 10 and ip != victim_ip:  # Exclure explicitement la victime
#                 blacklist[ip] = {
#                     'timestamp': current_time.isoformat(),
#                     'expires': (current_time + timedelta(minutes=5)).isoformat(),
#                     'reason': 'Multiple malicious attempts'
#                 }
#                 print(f"Ajouté {ip} à blacklist avec {count} paquets")
#         print(f"IPs malveillantes détectées avec leur compte : {malicious_ips.to_dict()}")      
        
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        prediction = model.predict([[
            data['duration'],
            data['protocol_type'],
            data['service'],
            data['flag'],
            data['src_bytes'],
            data['dst_bytes'],
            data.get('land', 0),         # Valeurs par défaut si absentes
            data.get('wrong_fragment', 0),
            data.get('urgent', 0),
            data.get('hot', 0)
        ]])
        return jsonify({'prediction': int(prediction[0])})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/attack', methods=['POST'])
def launch_attack():
    try:
        # Commande Docker pour lancer hydra dans attaquant_externe
        cmd = [
            'docker', 'exec', 'attaquant_externe',
            'hydra', '-t', '4',
            '-L', '/wordlists/users_short.txt',
            '-P', '/wordlists/passwords_short.txt',
            'hote_principal', 'ssh'
        ]
        # Exécuter la commande en arrière-plan
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # print(process)
        stdout, stderr = process.communicate(timeout=30)  # Timeout de 30 secondes
        if process.returncode == 0:
            print('output',stdout)
            return jsonify({'status': 'success', 'message': 'Attaque lancée avec succès', 'output': stdout})
        else:
            return jsonify({'status': 'error', 'message': 'Erreur lors de l’attaque', 'error': stderr}), 500
    except subprocess.TimeoutExpired:
        process.kill()
        return jsonify({'status': 'error', 'message': 'Attaque timeout'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
    
@app.route('/stats', methods=['GET'])
def get_stats():
    with data_lock:
        # Convertir les valeurs numpy en types Python natifs
        stats_converted = {key: int(value) if isinstance(value, (np.integer, pd.Int64Dtype)) else value for key, value in stats.items()}
        return jsonify(stats_converted)



@app.route('/blacklist', methods=['GET'])
def get_blacklist():
    
    with blacklist_lock:
        return jsonify(blacklist)

if __name__ == '__main__':
    threading.Thread(target=process_pcap, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)