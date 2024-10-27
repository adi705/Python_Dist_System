#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Wrong usage: ./run.sh <num_nodes>"
    exit 1
fi

NUM_NODES=$1
TIME_TO_LIVE=300
PORT=59423

SCRIPT_DIR="$(dirname "$0")"
#echo "$SCRIPT_DIR"



ALLNODESFILE="${SCRIPT_DIR}/allnodes.txt"
NODEFILE="${SCRIPT_DIR}/nodes.txt"

NODES=()

# Read the nodes from the allnodes.txt file
for ((i=0; i<$NUM_NODES; i++)); do
    NODES+=($(sed -n "$((i+1))p" < $ALLNODESFILE))
done

# If the nodefile exists, remove it
if [ -f "$NODEFILE" ]; then
    rm "$NODEFILE"
fi

# Create a new nodefile and add nodes with ports
touch "$NODEFILE"
for NODE in "${NODES[@]}"; do
    echo "${NODE}:${PORT}" >> "$NODEFILE"
done


# Print the nodes in JSON format
echo -n "["
for ((i=0; i<$NUM_NODES; i++)); do
    printf '"%s:%d"' "${NODES[$i]}" "$((PORT + i))"
    if [ "$i" -lt "$((NUM_NODES - 1))" ]; then
        echo -n ", "
    fi
done
echo "]"

# Start the nodes using SSH
for NODE in "${NODES[@]}"; do
    ABSOLUTE_PATH="$(pwd)/node.py"  # Get the absolute path of node.py
    COMMAND="python3 $ABSOLUTE_PATH -p ${PORT} --die-after-seconds ${TIME_TO_LIVE}"
    echo "Executing on $NODE: $COMMAND"
    ssh -f "$NODE" "$COMMAND"
    
   
done



# Start the chord tester using SSH
CHORD_TESTER_PATH="$(pwd)/chord-tester.py"  # Get the absolute path of chord-tester.py
#ssh -f c3-0 "python3 $CHORD_TESTER_PATH ${NODES[0]}:${PORT}"
