import re
import csv
import os
import plotly.express as px
import pandas as pd
from collections import defaultdict
import plotly.graph_objects as go
import plotly.io as pio

class TsharkParser:
    def __init__(self, directory):
        self.directory = directory
        self.rtp_pds = []
        self.conv_pds = []
        self.rtp_deltas = ["Min_Delta(ms)", "Max_Delta(ms)", "Mean_Delta(ms)"]
        self.rtp_data_dicts = defaultdict(dict)
        self.conv_data_dicts = defaultdict(dict)
        self.conv_throughput = ["Bytes-A_B", "Bytes-B_A", "Total_Bytes"]

    def _parse_conv_udp(self, input_file, output_file):
        rows = []
        with open(input_file, 'r') as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line or '=' in line or "Filter" in line or "Conversations" in line or "Bytes" in line or "Total" in line:
                continue
            fields_p = line.split()
            fields = [x for x in fields_p if x != 'kB' and x != '<->']
            rows.append(fields)

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            # Adjust headers based on tshark version
            writer.writerow([
                "Address_A", "Address_B",
                "Frames-A_B", "Bytes-A_B",
                "Frames-B_A", "Bytes-B_A",
                "Total_Frames", "Total_Bytes",
                "Start", "Duration"
            ])
            for row in rows:
                writer.writerow(row)

    def _parse_rtp_streams(self, input_file, output_file):
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        rows = []

        for line in lines:
            line = line.strip()
            if not line or '=' in line or "time" in line:
                continue
            fields_p = line.split()
            rows.append(fields_p)

        if not rows:
            print("Warning: Could not extract RTP stream data properly.")
            return

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Start', 'End', 'Src_IP', 'Port', 'Dest_IP', 'Port', 'SSRC', 'Payload',
                              'Pkts', 'Lost', 'Lost_Percent', 'Min_Delta(ms)', 'Mean_Delta(ms)', 
                              'Max_Delta(ms)', 'Min_Jitter(ms)', 'Mean_Jitter(ms)', 'Max_Jitter(ms)', 'Problems'])
            for row in rows:
                writer.writerow(row)

    def _join_to_results(self, file):
        return os.path.join(self.directory, file)
    
    def is_rtp_file(self, file, type="txt"):
        return "rtp" in file and type in file
    
    def is_conversation_file(self, file, type="txt"):
        return "conversations" in file and type in file

    def parse_results(self):
        for root, _, files in os.walk(self.directory):
            for file in files:
                if self.is_rtp_file(file):
                    new_file_name = file[:-4] + ".csv"
                    self._parse_rtp_streams(self._join_to_results(file), self._join_to_results(new_file_name))
                if self.is_conversation_file(file):
                    new_file_name = file[:-4] + ".csv"
                    self._parse_conv_udp(self._join_to_results(file), self._join_to_results(new_file_name))

    def _file_key(self, filename):
        return filename.split('\\')[1][:-4]
    
    def _get_info_filename(self, filename):
        split_name = filename.split("_")
        info = {
            "capture_time": split_name[0],
            "no_clients": split_name[1],
            "clients_time": split_name[2],
            "mode": split_name[3],
            "stat": split_name[4]
        }
        return info
    
    def populate_rtp_pds(self):
        conv_files = []
        for root, _, files in os.walk("results"):
                for file in files:
                    if self.is_rtp_file(file, type="csv"):
                        conv_files.append(self._join_to_results(file))
        
        for c in conv_files:
            self.rtp_pds.append(pd.read_csv(c))
            self.rtp_data_dicts[self._file_key(c)] = dict()
        
        for df, f in zip(self.rtp_pds, conv_files):
            for column in df.columns:
                self.rtp_data_dicts[self._file_key(f)][column] = df[column].values.tolist()
        
    def populate_conv_pds(self):
        conv_files = []
        for root, _, files in os.walk("results"):
                for file in files:
                    if self.is_conversation_file(file, type="csv"):
                        conv_files.append(self._join_to_results(file))
        
        for c in conv_files:
            self.conv_pds.append(pd.read_csv(c))
            self.conv_data_dicts[self._file_key(c)] = dict()
        
        for df, f in zip(self.conv_pds, conv_files):
            for column in df.columns:
                self.conv_data_dicts[self._file_key(f)][column] = df[column].values.tolist()
        
    def plot_conv_throughput(self):
        for t in self.conv_throughput:
            data_plot = dict()
            for entry, _ in self.conv_data_dicts.items():
                data_plot[self._get_info_filename(entry)["no_clients"]] = dict()

            for entry, val in self.conv_data_dicts.items():
                no_clients = self._get_info_filename(entry)["no_clients"]
                is_ebpf = self._get_info_filename(entry)["mode"]
                data_plot[no_clients][is_ebpf] = sum(val[t])/sum(val["Duration"])

        labels = list(data_plot.keys())
        ebpf_vals = [data_plot[k]["ebpf"] for k in labels]
        noebpf_vals = [data_plot[k]["no-ebpf"] for k in labels]

        fig = go.Figure(data=[
            go.Bar(name='eBPF', x=labels, y=ebpf_vals, marker_color="#ffe100"),
            go.Bar(name='No eBPF', x=labels, y=noebpf_vals, marker_color="violet")
        ])

        fig.update_layout(
            title='Throughput Comparison per Client Count',
            xaxis_title='Number of Clients',
            yaxis_title='Throughput (MB/s or similar)',
            barmode='group'
        )

        fig.show()
            

    def plot_rtp_delta(self):
        for t in self.rtp_deltas:
            data_plot = dict()
            for entry, _ in self.rtp_data_dicts.items():
                data_plot[self._get_info_filename(entry)["no_clients"]] = dict()

            for entry, val in self.rtp_data_dicts.items():
                no_clients = self._get_info_filename(entry)["no_clients"]
                is_ebpf = self._get_info_filename(entry)["mode"]
                data_plot[no_clients][is_ebpf] = val[t]
                data_plot[no_clients]['ssrc'] = val['SSRC']
        
            fig = go.Figure()

            for client_count, client_data in data_plot.items():
                fig.add_trace(go.Scatter(
                    x=client_data['ssrc'],
                    y=client_data['ebpf'],
                    mode='lines+markers',
                    name=f'{client_count} clients (eBPF)',
                    line=dict(color="#ffe100")
                ))
                fig.add_trace(go.Scatter(
                    x=client_data['ssrc'],
                    y=client_data['no-ebpf'],
                    mode='lines+markers',
                    name=f'{client_count} clients (no eBPF)',
                    line=dict(color="violet")

                ))

            fig.update_layout(
                title=f'{t} per Stream SSRC by Client Count (eBPF vs No-eBPF)',
                xaxis_title='Stream SSRC',
                yaxis_title=f'{t}',
                legend_title='Configuration',
                template='plotly_white'
            )

            fig.show()
            #pio.write_image(fig, f"plots/{t.split(" ")[0]}_SSRC_Client.png")
        

if __name__ == "__main__":
    parser = TsharkParser("results")
    parser.parse_results()
    parser.populate_conv_pds()
    #parser.plot_rtp_delta()
    parser.plot_conv_throughput()
