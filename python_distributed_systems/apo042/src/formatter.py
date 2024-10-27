import csv

# Throughput data provided by user
throughput_data = [
    809.3299681231234, 844.9202299209007, 823.4407197064884, 816.2223824882586, 816.2624118747648, 
    812.4751810115416, 792.9037797634013, 822.4789924205642, 819.6296652385743, 822.5344776598256,
    431.5311372315652, 464.8944763809934, 433.62933230885403, 435.09422727616936, 435.6317178391242, 
    431.8593999010317, 430.40592320407313, 414.499841485561, 427.4295734961511, 422.15396854345494,
    284.99159831735324, 297.34230409263364, 296.47926350671236, 279.44075392634437, 272.14657735922754, 
    290.6974681073792, 260.3107291511121, 264.0880511777385, 280.68819167325285, 293.2443195546925,
    191.05055430708063, 188.46686175811828, 184.23619951694434, 188.20981908397192, 183.7692432191479, 
    193.4486629349247, 193.4183679163121, 197.63239043977134, 193.96459593406792, 183.2067257242038,
    154.46416970883294, 156.44300792214133, 159.72571514918687, 160.57538942835095, 161.83290532133927, 
    157.50069544622414, 159.03797266383174, 161.68086572016588, 161.72109982735577, 162.73557215488105
]

# Number of nodes for each set of data
node_counts = [2, 4, 6, 16, 32]

# Preparing the data to be organized as columns for each node count
rows = list(zip(*[throughput_data[i:i + 10] for i in range(0, len(throughput_data), 10)]))

# Writing to CSV file
csv_filename = 'data.csv'
with open(csv_filename, mode='w', newline='') as file:
    writer = csv.writer(file)
    
    # Write the header
    writer.writerow([2, 4, 6, 16, 32])
    
    # Write the rows of throughput data
    writer.writerows(rows)

csv_filename
