# Running the code on the cluster
While on the cluster in the src folder , run 
```bash
./run.sh num_nodes
```
where num_nodes is a number between 1 and 32


## Testing the Endpoints

### 1. Test the `/network` Endpoint
To retrieve the network nodes, run the following command:
```bash
curl http://<node>:<port>/network


```	
### 2. Test the GET `/storage/<key>` Endpoint
To retrieve the value associated with a specific key, use the following command:

```bash
curl http://<node>:<port>/storage/<key>
	

Example: curl http://c2-1:59423/storage/myKey
```	

### 3. Test the PUT `/storage/<key>` Endpoint
To add or update a key-value pair in the storage, use the following command:

```bash
curl -X PUT -H "Content-Type: application/json" -d '{"value": "<your_value>"}' http://<node>:<port>/storage/<key>

Example: curl -X PUT -H "Content-Type: application/json" -d '{"value": "myValue"}' http://c2-1:59423/storage/myKey
```	

## Running the Chord Tester Script

To run the Chord tester script on the first node, use the following command:

```bash
ssh -f "${NODES[0]}" "python3 apo042/src/chord-tester.py ${NODES[0]}:${PORT}"

Example: ssh c2-1 "python3 apo042/src/chord-tester.py c2-1:59423"
```