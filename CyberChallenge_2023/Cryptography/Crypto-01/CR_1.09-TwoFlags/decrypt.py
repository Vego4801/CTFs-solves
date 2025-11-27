import numpy as np
from PIL import Image


enc1 = Image.open("flag_enc.png")
enc2 = Image.open("notflag_enc.png")

# Retrieve (Im1np ^ Im2np) <=> (Enc1 ^ Enc2)
im1_2_np = np.bitwise_xor(np.array(enc1), np.array(enc2)).astype(np.uint8)
Image.fromarray(im1_2_np).save('xored_flag.png')