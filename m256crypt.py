from m256 import Machine, KDF
import sys

key = KDF().gen(sys.argv[3])
infile = sys.argv[1]
outfile = sys.argv[2]
inf = open(infile, "r")
data = inf.read()
inf.close()

data = Machine().encrypt(data, key)
outf = open(outfile, "w")
outf.write(data)
outf.close()
