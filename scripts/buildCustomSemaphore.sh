#!/bin/bash
cd "$(dirname "$0")"
set -e

help() {
    echo "Create semaphore circuit with custom level parameters"
    echo
    echo "Syntax: buildCustomSemaphore [-h|n]"
    echo
    echo "options: "
    echo "h Run help command"
    echo "n Number of levels of the merkle tree"
}

while getopts ":hn:" option; do
   case $option in
      h)
         help
         exit;;
      n)
         n="$OPTARG";;
     \?)
         echo "Error: Invalid option" 1>&2
         exit;;
   esac
done

# Write custom circom file
circuits_directory="../../semaphore/circuits/"
original_file=$circuits_directory'semaphore.circom'
regex='s/(20)/('$n')/g'
sed -i -e $regex $original_file

# Extract constraints and compile
cd ../semaphore/
echo 'Compiling circuit...'
(time npm exec ts-node ./scripts/compile-circuits.ts) | grep -e 'linear constraints'

# TODO: Get time to generate proofs
# TODO: Submit a single message to the circuit

# Clean up
cd ../scripts/
regex='s/('$n')/(20)/g'
sed -i -e $regex $original_file
