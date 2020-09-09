
# PCAP to flow conversation transcriptions
FIV, Sep 2020

Scripts for transforming pcaps into flow converstation transcriptions. The meaning of symbols is explained below.

## Example

    bash run_pcap2trans.sh

## Symbols

- **'-'** stands for 10ms without packet exchange.

- **Uppercase symbols** stand for client-to-server packets (A>B) 
> symbol = int2ascii( abs(tcp_len/146) + 97)

- **Lowercase symbols** stand for server-to-client packets (B>A)
> symbol = int2ascii( abs(tcp_len/146) + 65)

## Files

- 'extract_features_from_pdml.py', script for extracting features from pcaps (python).
- 'README.md', this file.
- 'run_pcap2trans.sh', program example (bash).
- 'symboltran_lt.pl', script for transforming packet tuples in tabular format into flow conversation transcriptions (perl). 
- 'test.pcap', example network data capture (pcap).
- 'test_ft.csv', example file with packet feature tuples in tabular format (csv).
- 'test_tr.txt', example file with the flow conversation trancriptions (txt).
