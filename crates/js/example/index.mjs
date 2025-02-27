import { compressProof, decompressProof } from "semaphore-rs-js";

const proof = [
  "0x2d77679b613036865f4518894c80691cf65338fe7834fe3dd5f98c4f0f5a9e6d",
  "0x24018e845edf74d69528a63eed053296a397df13a1d08873e2b2d673837b31c3",
  "0x099d39b2cbca524b5916ac97dbc4afc1b8a5f59d65ba583fc49ec2677226e926",
  "0x0da5812d7b4e0beb22d25c194431674396aec70751873edb9ac8c933ba1f0f2e",
  "0x0723caca23efb9aa44db59ead0eeb28c2efb9c766d9a3f994ed047179e37b347",
  "0x02166d9fc2d4cf446b120e5663880e0927825aa36a02b896ac0f3a5ef6e0239b",
  "0x287fb1d0415a734ba76df9eb50ca6758bb806272f8fe40e3adbad3a850c05167",
  "0x1240cf8aa43cf4ea4a2d8dffac653a6467cefd0f19e129cffad85299d6705444",
]

const compressed = compressProof(proof);
const decompressed = decompressProof(compressed);

for (let i = 0; i < 8; i++) {
  if (proof[i] !== decompressed[i]) {
    console.log("Proof not equal after decompression");
  }
}

