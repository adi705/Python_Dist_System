import matplotlib.pyplot as plt
import pandas as pd

df = pd.read_csv('data.csv', header=0)

mean_arr = []
for col in df.columns:
    col_arr = df.loc[:, col]

    mean_arr.append(col_arr.mean())

plt.plot(df.columns, mean_arr, color='tab:blue')

for col in df.columns:
    col_arr = df.loc[:, col]
    plt.errorbar(col, col_arr.mean(), [[col_arr.mean() - min(col_arr)], [max(col_arr) - col_arr.mean()]], fmt='.', capsize=4, elinewidth=1, color='tab:orange')


plt.xlabel("Nodes")
plt.ylabel("Requests per second")

plt.savefig('throughput.svg', format='svg')
plt.show()

