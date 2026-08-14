#!/usr/bin/env python3
"""
  Big thanks to Claude which pulled out all this .rodata stuff :)

  0x20C0  byte_20C0        1824 bytes   -> encrypted MAIN bytecode (228 x 8B instrs)
  0x27E0  dword_27E0       116 x u32    -> per-phase seed constants
  0x29B0  aHhhhhhhhhhhhhh  116 x u16    -> per-phase sub-bytecode LENGTH table
                                           (IDA misnamed this a string literal;
                                           it's really an array of uint16, read
                                           via `(unsigned __int16)aHhhhhhhhhhhhhh[v16]`)
  0x2AC0  word_2AC0        116 x u16    -> per-phase sub-bytecode OFFSET table
                                           (offset into unk_2BC0)
  0x2BC0  unk_2BC0         up to 0x27D8 bytes -> encrypted SUB-bytecode blob
                                           (all 116 phases' programs, packed)
  0x53E0  xmmword_53E0     16 bytes     -> initial values of the 4 main VM regs
  0x53F0  xmmword_53F0     16 bytes     -> per-phase register-seed constant A
  0x5400  xmmword_5400     16 bytes     -> per-phase register-seed constant B

In IDA: Edit -> Export data / or just `idapython`:
    print(get_bytes(0x20C0, 1824).hex())
and so on for each table.

The sizes assumed here (dword_27E0 / aHhhhhhhhhhhhhh / word_2AC0 = 116
entries) come from the bounds check in the decompilation:
`if (v16 <= 0x73)` -> valid phase indices are 0..0x73 inclusive = 116 values.
--------------------------------------------------------------------------
"""

import struct
import itertools

MASK32 = 0xFFFFFFFF

BYTE_20C0_HEX = "00789d7a10d2226b393a0b0e405ef058b276a10daa491b8967bc879ec57b448a278a9d24d2ede0f1ace01e4952f84eac9fc18b95dd59089938f604703a81ba60dff59c52f07a64ce6c87d49e2981554bf966c782a8c224c887375e43cc7a1102078e7584764e73f01140f6b39c68d6aa4342c904367652802e8ab85aae9dde1bba55f7b8da9ce9fc4fe08f21f02f4320c34181616314cd64bd11168a15fa2f8a94bd2f61abe880e86d41d9567008d42836909fdc567256660608c397efc626b5d82459cc8e94f08b1899eb6ff96bf45c9051ccb1bdc65bc2a60ef3b8de80d246745ddee213e08bd7905a35ec71404dc21e3ce5deef863754be31c72299e24a02d857c57ba23cd83589e3ec15752ab5f3e8ef52b67b496bebba36ecf8224584433e1df421542961f2a09869ca956f9d45d3395cdf1205a4f3b1d261e180a997bb5b267daad4781a663e3d042af9719f6f2d216c4e59b565a76f1e12a22cf46140d540fb41f0cd4c92c8716fb42a931819dd5be9b59de8b44f2cde754717bbfab56101034c7e01dce970a7b94bac30f0dfd11c8f64f696bb32aab812eef93215c4a2e192710ed8b1a885e7afef1ec8e9b007e3fe34cc7909e48579247b3407d97430d41c7f89460b465c746538f71adb19598470dc67cc7343006f36cde9ce9189631ba1b8fd9024bd4add80c2cfde43e63d962521e57a8c89164dac7c0b5b90206325a1166bed1f01193a352b507b9a2fde892863618047a61c81a97556f3585cdbf29b3a47bf30af64b105942cbbee5ff8d193fd5ca03e4a275101bc9c0506bda687e330014bb52520771ef85ea9949ae1663410e7b4fda9c2c69027d89f9358ce80ed349a4e2b0a391ff7c19845cab1e92c1d818202670fcd9a8de87c2c20813a1d2b398fa600c14e84fd03ebc63137678dc3f67f21b2bc6b74d2b4fa3501170a8049ce55d6e6065f18f8f997303237c4d2d3c335432babdd928af74fcbb3ec4fa230b2e4aab8b645096238c39494ad69f15c53dd4621a9a0cf98a0a4d8a8725988c819c65b1061b1504b76927e1311eda8c62b7aacc1c0b9fc1268b79ceb46ebb96b52e122f145076f5bdfbc50959d39e117e6d3ee7415937a41a250d49333bbe28ab0d70129de648a7c515539cee1bbbc462dc80d337745cb5fc69ce20b953ac760e316ea6f04131c9e57f017612521ba336073d72234b1efc9e4e89ac3ca0134d97c82153511b6225d765583fb4112410c885ea527589e1de1c2b04ff5b930bf2ad0857fda9f271a9b3557ac078ca25083f987b7fa6685cded6648342c974610cfea8fcc64d4afa7179908ef2e84fb93d6e8ce3a87188bf19184ce2e0bf1a04ad6f74cbb2f9385ebd72d5ee1bf47e0441c36a80fed309cb42d35d5583c3345b119f011488eca742e7e73028e22013f9487af23cbd8adc3477579c119a786fe152805e72a22d95dc32e31a13cda50bf163f87c330c9fd60b911bd5cc3af3367162d6424fbef6d046fb1408288ed6aa5348e2adb5259883b44944a0488b51a1146544c33230e3b94a307738ebf0bdf5c98c81aaeb2281ef921ad6e58be371fe6821370f25d599edda02642cde050b4ef57387dbdc6c6db3d1bad6ed0c7118d39a07fb3fd52f038562747e4c6a2325d0f864eb7612d9d5400158eae8bf361008f27ba3abc57b8726f439cc15b5f52ff49e5f39665c0399e184581962ce43a5fe83ee4ac4b32dd9e79947da45d97285da91f021d82d128a5234f230508b793ce72c729eafa6a512d58ab4719d54b291575beb78ed8ce5344ee3da63be2d5338b01d0b6c625f5d89ebccff046c5c90d4fcabc662b9075cdea97d15667b39e251ed04cc20b8edb6d1f2125371a38a7755ac4194d83197137eca8c6a8af03183ececa3c24c50644cda5265c6f5e71b51b5fdf9b7e8343ac1c71d14e2adc9874b4c156153036ccafcd4eefa0b412e1a3907f014efe8b5529c772e6c219e5a32b09f5a716fe09c5c236705332b2307355fe16b17e1d557c23745d92dd8907cd5eb616b43ef872a824a20229790fb46fb5726bd10fe4adb493c1e1b61ccfa00f713a2ade56efa809bc6b9d05be99eb065a87b4aba809c959285920f29d5b85e35ef85839e1366e2f05813630a74da3bc62c6a62a3f3c73eefb0ef27ed864b6beaa8febfe0c81762b9589ed6a370cdd1890a019096350f7d012b50dbd6af6da3fecc8fff5ce8400b671f111730f3278a89191a7a08ab13c2c61a27440521f48455def0d12419c872e100c68794e883468e81caf65abe5324bfb54be7e660b66ba7d7cc0755588b5b3722bb60fa20b559b525180e24e8a78f41cf36f49787b3d6915a08b3279ace49e4dd56b80656998513fbd8a4f2ff7d7ab2a58d0a3d17800dffe16cadd967f28a4bde55edf1de55f36dda934d11b6353dbc9c5184d981e3fa9cbba4411e61f6620682c781d18a13afcddf1f16e78eea11fa0b4f1b64b61659326d7d32ed5c69f8d82aca1bbabc384abc60a246b11dfb0b3f5cb68231b677d025c3e64327d493f4cba3c7a58409070f43abc604b575bd0776b7308209704482fcd1d6e"
DWORD_27E0_HEX = "5aff90ff597c44df26c5c7be8cc050c2f24b12bd1b59938163c036e02fd75ce8290cd1c7e6a1ad69845912be33d873b37b7740bf433ada10ddbc7c645730312ea18bc12577fbf11d487e5c27b0de1e7085c159bb6455424ee5545038aed37f4573d63e84cefea170ea7ed897a600da43f110610fa6286967b709c6ccdd1b4643cc4f5c248fbb28fb0b4198a7b7855189edff817134197c139aff13e6f1c73ae7d27371e1cd43d742ceb515118d4ca0229e1dc235527a27ab3a6466819b0d9bc04487fde05853c6bdaf59e96a20472ca9294f42f0a372e8c3f270d136db6d00e4fb4c74897545a51cb8f82cd2b011d65580296ded0d841dc968e5a8e377f23077ad8e2abd29a22b5602eda031c809d4493dd20c1a9552d8654b2acd3dc4ee7b010f098973d921552418570ba104cdb3f9ddc21b31de03fd677c0eb99a257668b261e2bff2d0697d2845b95ded794432cc0220d7f5f25fb77db3c1c4f2badc03148a5c17f078e159c3a0fe92cc9498ad10ac7d607f8d6c0905ce3cd09d61ad91fa5d10415c9377ff5d1ca4091c904e96f891db70df4aff33ad9941b38c6d7244b16c493c2c83ddbb33064b2a93ce7979db3587412cc67c2cd79f01a28f734aa8c2d4a6d0edef2d2403cde72094af28f7e6"
LEN_TABLE_HEX = "68006800680068006800680068006800680068006800680068006800680068006800680068006800680068006800680068006800680068006800680068006800680068006800680068006800680068006800680068006800680068006800680038003800380038003800380038003800380038003800380038003800380038003800380038003800380038003800380060006000600060006000600060006000600060006000600060006000600060006000380078007800380070005000600030005800500078005000300050005800380060003800300070006000600030003800600060006800"
OFFSET_TABLE_HEX = "00006800d0003801a00108027002d8024003a80310047804e0044805b00518068006e8065007b80720088808f0085809c009280a900af80a600bc80b300c980c000d680dd00d380ea00e080f700fd80f4010a81010117811e0114812b01218138013b813f013281460149814d014081540157815b015e815201658169016c816001738177017a817e017181850188818c01820198019e019401aa01a001b601bc01b201c801ce01c401da01d001e601ec01e201f581fd01f48208020f0204021a021d02128227822f02240237023c02318245024b024e82418258825e82548267826b02610277027"
UNK_2BC0_HEX = "a919c67a932295286072c5dcd35fbdf7898cf6d41d5a82c001843283e69c960b2155cd2715896685ca42553ad79649fc290a497a349fee3b1086704918fbcbe72eef7b9f01909da824a9a6597d1df4c53e809273854925a12b0f7aed8d920670970787718852d6f81c7095c6a8c2848701546f5d01e1e23e790d2768c0e0eb036f8068d87aa8eed5e4de6cf272069345729e8bd3256c09ccec9f8881bc4e6728f1fc4e3dc6fabe23faa21d34fb088f617eb9eb02b2ce79de60b1c8271cfc442b405ade63c17e4750ecdda6580f79e9b1829334f840382db596339e51d0ccb5991c5708c90e6a31908e82468ea63e0829a50f241e6eaf6bd47206762ec13b87550df48ac8a2a75ae072424e0a81fa9513e1a1916ddf5c44e6d867a8db0935c1582c76a0536b556010c475b0f9c7b2c8d9a50f9d2184bd7b7536c9045d0095379b27b2d3975446b93bf0f36a7b1d64fef20293377dc9c3897ccb672522c769b535bf739263dac2453b4820576cb5a37f699b9f03b0baf03df4e81ed868cebe34b5ec6b61b645b45f5762a2e4c16a245c8932616d3fb91e76254be798e6b3a49b88eaae79eb9a44e2c9ded2a837f19a6855fa90e254c3fc946cb4a5ccdae324610914db3717d04bd7274a952e5d0194794bf88033d35143b8d192b929a1ae705916742c574d44cedc248d1b88dfd589ee2b47cfcf5b808f1824972f4141a5980d02d8ea88e37e429dfe18624bcd48ca0234bc06ee25d543f17a68ab7b67c34500b3eebb37b06eec646764905768c656ea4a737d94ac6d65c264cced5fbdfbdcedfde5942620d91a37633fe48393f45a744cf23f867f22d45475f385730713655103fa9d5bb8ce9e528141d61a662fbe9ca1118268b565a64d523f3427632c01b00958ed02bf1255f38eba0985159c6a39e521462159d4a19d0ed6fcd2e3f9af262deaaf25f86f3e06f70495d80bc2b8c7d07c9cdd5fd4f406c7b5941c9135d269d94ec4e769faee14267929b4058e7d4008c29b2d9a2d06d26e6962fa96df41190c35b577bf4239997c9eb70ccdad93573cbaad0a237b1c7c92e612a804860be06b5b997d232dea41e87de81305569b79c57c4d76883f0e48f41c557a94e7e2e6e1ff5d9616269b10efa0c17fab146c05f6db4699ae1d07a8603181769a412171f1410959ef72f79cf4610133d0e28111c6a0b2cc5b4612b3276360f9b107468812f0298c59fd045844525e0886e298d8abd8c23c8a75498513b96e32d57b74ce2957437f3599c3ff0d31fc45ac11c078953476740a045a63dce45d2aa5248993bb1abf683881a0a51d23261dc13d36e8d8f219d4fb3057f19bc955ed156f97a296b2da56f1d206f720c044e018348546038096bc22955e8e34176be9ed2441fcd4ae2701a245c8f5480784a953dc863b65233c8094e7b4cab0fa36303f1be50b59b6d43c1b8db0c1dcd7442995cb4d6440c9cb500cecaccd2f9985a091bf9cc93c4d01aaa7cd7bbb319588431106598f80dd0ce6aa9bba3abba708a88bcf783df72007357271d04a9e497138d0e6d7cb6030afba41c04ec5e1fb1a55e4cb2a04ff585893a2a2fbf9a44873721c2c0272149d350da6293d466fce84e01101ac04a1f747722f03ae2910c8dadfb61151dae88072d47b64e80493a3a4f411971b772d6bd5d0e323a18f4b262932550b5f682719f036e0e64e8e0425c63401763132d6d6bf67217f4de377a1e57fb96f87409e3407a8a54c3961838a5f7619610cb810a7bcfbe7d2c65c1d34a1d9d1e09f0dc9c2c8e2e4fed55070052442d5cac892b461e0c7a5eef6701dfcc40996b5b8e6c07778eced82e1b3d6c323a2c88133096feff54116772a04bdd06a592e42c1cd8eca5812afc82e8c5c34cf84511a652fd0504f39a0bb620bb829ebeebfd373e8063aa7b0975eb8a046fa4548834a6b0f96df641079efa6cedcb2b63ed9ef32e8c107bebca691faf817196baceca9bfa74288a309d9b54dcd6a2bfe5aefa8c813956cf214e49fd9e66371b4a74199a293af6315ab770e4b92cb2e1d90f8cf08233421b36afdc99a20931c8b2d5489cf73e55d43906e964c70d2116dffeed1faadaeeedd95c95ec911d22a7c4e70663c2f3376af6dde9391f54d43ef611c19ca75f307768333ab669245538de925f556ccd7d2c53958d29d39310b0102fd9aaffacb5cc3354978052656eebe79a7fc240a813537ccddefb23cd63cfa21eb0fd8c2749613e282a65f133c9b7494c66716e923aaeaedf213df37c9c27bf087286f6c8830308caee4b389bc269f5259b287a8261298bb93f66f136059dabe5fa8e289dea8a0a2a63c438a94fb74349ee842f2af78195649aa52ccd392501cb66440ef004ab24d447ba17cfe56f97a632ecf347a68a38aed2d22c6f327f12281ea604f90632a95c64214244697ac497aeba311e6c7837c1acc0ddfc1dbd7bd28be90351b15206b728381350826bf75e93d7336af3715aa644ff518007408bb23d60f3d81bbef0424bad66fb0b4fb4ff2f393406231df2bcc0abc7b9528e8e5791b0e90e2c17226813f48ea821d39026fff51c8c1ce09ff7c894fe639be5ec81ce95b2f13d4a5bc9463a97bd19e9b4c28a03dcd6c57c733c1d857d7393ff31e1f73c5f85dc7510cf4211becbdc9680a2442b532f69ebf90b2d74f5a4f06b05ee1c3746edacd87c1b2249a308962a7763e730bc5b68541de51a67b4643c6c301c9889848acbcd79993e2063c621a4beece46e1980ce53d40e4849b959c37a07274a8fdfe943c941defb73e2961a8519990490ed5ef054aba3d22c394ffc0b4ff8b30f4c3922652fa5f383509b1d70c121f34e07722f3f72357a40f8f1614d42029f194f457a043e3dba5b92d47db2e77a9be7c1e60c52e483140bf87c97cade00eedd476fda894564f9fe82194fc06cce31ef7e9f4dfeea6595197c99c89d7e16853934bbc0d1030cffc8e48e2c5e83efa0f93706987080f1cb9a179b37b0abe681da84282be24e2da9b18f451ebbf8d593a5438f17c36d5295b3eafbd4a2e97a01ced682ca4135a5fc84f4879b026904547a8cf97538faee54c11c2d84c639c05985b435857b69fecc1acbe613b0547ea3a40436d4702e60f597acdb0301c24b20ad5a1a2b97419591d0fa952a20146dc10f9d44c8e1b71f7f71fa08406902c6aad42ff930520a5b0a57c420b1bfec55cca8791575c3d399a92007dd3efacf454bc5d356c162b304dd332b7afd11b77c8dba730cf625082ba0673362cee13eeccd6fc18d3df31804ed6b228778fa23ab6d8135ab85508cae7a58a8f0c92319b1ec72b3e48a9302cc1c23fb4082894fb05d46a51d9e48f85c04b29654e436f1d78da996692bb992cabbabe4f8563dddab2a8e30b9826c84d570170fcb055a8b3cb26b3fab9d68814f88e30b82142c1c88996244137c4cf2bd9fca92fe20ffb68461d23bab92980ff4425cf3a0d6df8bd5d58dc67e005ddad1e67b9a0f61289d16c7e5ced2033b8741d25428b3a7b72343bc5ceb666a559ce4790bc7f3e4f26d871b697689bd89a4be2846f69606a79becda7b427f38ea4c02f73ade71d3cde9d298b386d0b0da9ac9ab2cf6b1d70763a53a6273708f14fb11b702bd5e43c1378069c0f38b92b43c58f327ca38e005fc4e53c839d0cec37810a25f215152796d9fcbd3a49950c22bf7541fcedc9d1bab55f49b91de0a8ee647c76cdef3105307d54d16feab8486cabb0ed5ca526c28aaeb83e8fb20ed34079eaf60f5972e457f20e6916b4033197673543f9e26142f4bce347cc0102fca9319106b570ec3d445916d4b57af6f9361da906ae55e1a51f734f91e5ed2e3249fddb1254f2c316595f7130524522d5c132d56f3bd88226443fa39ba8e3cbc6928321226074300f9158e8c8506e1c4a46d52e9e7d81abc5a8f05e2ee5d14561ddae1c9c82f97836c80b3aaa829ad87667474805bbc9d56e8e281124795ed89a48a178fcb68f56ad33b34d335b28561ba1ebcbe9dbe46bad7f38ecc46bbdd081a1a4103f89b1764caa77eda0a66ca078e4513c85fb7868d9bc7fcb6dbce36c67fcf80e21f4d6f038d33966b19db083c16eeb1aea4302e82e9057785c61b774291bc6b07969d4a47e542eadc24172c0b63248277089682bae67fbc30632db4222e146bd310c58335ae252524d796207b9d70e8fc30e378e361fad14bb046e8801188505cee03a1d25e60ad20e423e95f01511d60175b8b2915bc1f47c32d2822a336a3588f4805cebadf29bd0df1c4ddf5dbff5cd03b52fd36231940805dec703ae99aedf784e48c113b604c64046f586209ee73457f2fbc4923060f61fb08bb43e537c89a2b0d6348620b410945fdf41d68b4c826bf8be4af643a67220f28575008128433001cca098e656eb9e01824d7650bde7bd726353f91dc951949f8eb84bed8823e5eb39757b22cd5a1b22fe024018a690060a4baf93b01fee66ba5f6ab8358126dd52758aad9304d87f76a70922e01830648eff4d38340714a8c141008bfcd243a655ad37d5355761f0c7dd4861e79f0f708ff9398f8edd60544e6025043e57c815b0c3bca52f8327892b3b33a99c372d4336aba107806b2ace0fbaa376a0bd06d4d1fde830da787d5152544f1c171bea18c19d4228d48abbedac87596cb1aeb3589042681d46cb13eadb7cd0eeaf03591b590023aeec3f2c39ed79cc65fe4878dd82e1e7bcdc69add35d03d32bda94391dbbd7ce33f7127cfb620d602ff473530897052a89705c835609bd5475550a61216ed5b0728d7b2aecf525d4b2153f4e188e94e046f0fea3ae7fc70019faea7c443714ea48916dbb210675647d146df5906310ab0228b07fc962e7a9ee2d331bb6f835c4582491ec718050f5211ac4423336bb44c425a6487552045c30077231700c79e3fc0b922c6b3aa2035d2ae304c8acc7e9aa8c56e9c3462feb1ef43c61d9b0645c196e8280db66be953caa7494460e4392ab5ec97df8d4f8ca7e8a68dc3d39942f1618cd08d625afacb57e3f8c90f13e2b4782bb0bb7507350d649d405fc7f36a2627df224e21c09e26c204ee64d2306e0dea1c721d19a8a9199ade407b0371ef85e55366167b800586d7bd9fb8a65ca4935f6a8c05e2c441757a03dd3f6c1fbc5a86e018243a0e45ad02a5747f754da62243b313c8c0c466323de21e37df36a11a99c322b5f8b9a64744c37852b9e39e0f6d3265d44826be471a4075b72d34d957d5b860121d8e6b3ae857f8998dbab420a2a615883f8d7ae452c0934b13c6315340f94e2b2715bff0bcd8882dd89273e4e8d5a6c9c4e02700d9b58ab1229cc016f0ff07c133892881c610a5532e8adb0f8b74520d5ace1d179f34b6d8d20dd7064654dff945a172dbf6d34e8042eb418259003c024ffb7f551a4a8492c2818f136eba2bdd14f3621fbc9a91199f95dc2c996c8941ff955ccca88b8a0282cc3d56cdae1719f049d734b747f2b2fc65345c7f8b8894f096744cbb940f3ac7795eb6c66c878ce015ff5e6af5c3b85fff74fc3b6aa1a3768341b04b6a042c67f173121f14fb7c1189a1ad6cf2e53c662bd011d149fab3d8f9a16bf4046631d5602251e683b7d22aac41700bd3a351b91a573f4ff44d6c77e997122537920ea4c726ef4f0b4f34529ef9b23681faf9bf1f9ebfde0937c564775533db325ae12074d3430698a6d22eccd93996b773a3f84b857dcde0fd1b4acd7372b5ec300f87c9382cde01de243a7fd906df992e0ce8ff4a8cc208379290e9974966f32f154e02bac8b85c8cdd730bff49a37f1871eb9d07eb043b735df66b7c79257e770462991aaf75ee3eaefcfdae7deeb3b0541f164ffe4f276d2c7654a4f78ae8972e1b2b705daebf6510260c3cda48fb3eb169f9d08006bd62daa273f68a4abb77c80f70ee3fb12c6793e5e8170b26e217f86dde648f4f5b463b61a68d4aa7d126c416d9d663976ab31ab44af69d7e4d5798e3a5421e6e647e39f9184224dd61e7e19cfaaf85cf1cb34fe7ef3ab0398f40c89ed014979e2b82aa51621ae5905965e52093c5c22be2c4a80880c82ffba96523974cf3fa67effdd6d13e753db390064b8b818dff40051084a3f9a503d496dbafafe225b2732d0567244ac260be5b32bfc4b14f036a06b7f6bbafa5470cd5543d1071678d972323b4af13384c01971f7e97afd36c86f7fb5ecdb70154b12ceb711f10a7e384a2463dcb83b1ccb58ed1c12d81a9400505f3af4db0893e3a9044088bad4852a0330a23c0252937176a59160c15a1f0c3e6eba47ed63335555a05f0412ed86c97dcc79b428a97b2a7f1d80d4b2defb5330dcff155fe5c943d6dbc89d0720d8ae4643965525171e6e3072811b840d031debb331949f0f1ac6f9ff3b91a55786aa483743977201826301bb4e2dc7064476bb98870449651c90525cbd10150b941e3c6a457679f500aff0e0ed4b5ebd6d31d7f526a633af7e12252271338f96d47b9b9db25e6d9bffd6e212c339408042db3415ada1de3493047a5d27335bdaa68d358fde91e03c0753c4329272819ee1415b2f3588d8a58a5597d5e5366a101ae5c6852d883032674db14a168f44355613c61a96148f91c85b74a10add3cd91d2dbc9c77d756fa3f7bfa47659f21c3259894b013452b6c25529636ff4f5224a2e17e64dee5662c16efb06bcf6bd685bfca3a12a13335287ede14bb7bc97256618d04814688251851da0e79cd32315495440e850c3ab0cbe961abd03da56997f0f81edc3dc12bd6ee86e669b78c4269d4a23059909a5909433bfe910f64dfaf7092b4ea6f1749d4f2d16f8f033e7aeeec48f719536e824fc89396d75f6dd06c58e7a98633fdec29ec2734ce8340df50cf917316bbc2668b3139754375468181e3eb38f4d49a66b68262ffd6aae2b1a37714079b84d92b7b3e5f0dc5397366291bd31185020ef7e47d5313a1db77fd485b4617794442d642810bc5757c12393efeb0090b1dcd955cc6ee52d35eebf19b356a6256145e3e40eec7ccf33894cb78143150ae79bf32da880b3271a18b679f1525b32c717b87e11e2c272806e663a64cabc4ab0c2be578bced6de2a1351aac26d0edd3adb0896879f9310515a56c9d956e0f6efb1ecabfb7bceb9332453478ba9620b738ff979a89ba3b47b220c4fecbe729369d49a83fc972db209e64f727533a79adad1f13c71bf9df57dec2a847c82a1d7c29a0ea4f355858b5ca5388eca76feb7a28ee20b9106d1c81f907ee3cba30272bed4a7e8b306f5b884e49b69f919152105012f8c5b1dc1bbdafa171c3728195b99547e5dbc85d0298a7596b48bc371909f442b86ad39f69f5cb5748bba768fe464fcc3d235b22e645e182aad1db7cc7263720331bad21cd0a7e6fc5184849625a2a2ccfa1ce52b8ed0426a1d9fac3a78922e0a78bfaf49364bd4bbb35f7a5edf70d8d9c6885abf4aa6e7d601a6c2707955d783d0de4495ad0d59f0b5a22cc1ed60f93dccf6f838ec7073b138c0b07ac8bbb841f39f02712b8ac74fc046cc41053bf0d47465b15ccfa4f6c4f33bcdce8271b35a74744376a1f745ae58e6570c6629c8a79325cff2754ade232ddedf62cecf3e3effc7121299b148b6218eeaa722f4461e816702c3a0ea420034534454a6e4e8f61aff4c2c425cb1e210ab0a05223fdcb120929b9119db163ed7af184e565cd0fc082ac5e699eff011c763ec1c0ad6e0f2af36dfddac088a681bd7fee1df0ea3520c7f6a7b18ba079644a692e9b2ff6c30da9d02c66b0f71e3c6e2e49b3895db1c6a3cba68fc0e16b2f47a7015340917ba53eaab39317b2e749b4d4259af6732a7198e6b411c8cbfa17b23bdbee0fdd67249bff0c8b4f0bdcae17151307961804160197075aee399862562206be12feab0c398e87b291e860842a24d9542dc7ba487b744bcdabf3740ec677b026e4f13ba5d795e2ee68bdc538a9208d437f914bbcab0ecdfb856e41709f0cff75c3e338d28da4e9e060767ba0503158153cee7a35b9b268b31d23b75bce65e3e0eeadd863916eb82a661f3c3c23db81b5cbf782902d2038fd616211d7d9a0a849ef3b2c79cc75727a20bd80a72025a885324355399b354cadc13423d839214a41c2ff2f3b0a1e4d84e5996a9422a439ae9cbd453b95e50d77242f4bcd983a618c97620381f52fd2f61ebc9dd5caa508aa2841db4ba596bf448d5ed6e8f3e02aa8c294ec4122ca32b590c7351dd62d387a836a8166af0a0de3d31417fa710cc830fb96ebd79ddc962259bf2e5c3da9c41f3d9abda7c83a5710eb16c7adff9b54697b75a942d3e9b0c450227fb3e1fc9152b8d169adf25a940f5bd2cacd5e2799428c819481a9f8875e15dacb31c80e23480ec1d8713796f031bd5b783ab080f96c0854e8bec9d3d7b527d4ebf85735671bfb9b937d7ac8079f0ac3ce9babeff7449205b1674ef77c73f5eb5ede1b0ac3800f8077a03db5cabdc076321c5b02623660d34e8d83760a39fc26cf86ab156628eab68a11890a8530ea3db107118c9139762a30c70d6de866a7b4d5d4f37a948360907cda460658540e6494310b2a1a1e04951570be2aa7e065449d905a30bfefd5cb75a9725317232bf89917627e76008e05e75581f7f3c3a30aaccb5b939a7ccd942a2cddc079d67da97d11b3a2d0ef377dafa8c6df60b2b815378efc0a2e4b31d048c24d19c652e8b133f01aee01e7e69f5ac1204a1268f4936c494aa96bca7896a26959db50ecc734a4064f3949995fd79dbdd03a8ea4f309efbb5659c6e31787e3a8101e5cf75ee3f991724dd38155195b5df5fdd4d69cc0e0e67a65ec185abd59b0d8f1dc3b87e472c757954053874968001dc03095a12fe04e8697834c49d57e6b08319fc2cc2b9b50da801596e242c74153c48c6989d06a875583e08ffcfe79da027cb911228f697369ae4e171308f17920ba9b5e9eb23744630fb5f522298810a24225ff9edd96dcab8e6e6ac1ad1a0fffbc618249466cf1cd33df4b01eba05d335bd7295f76c3f072c1c2f4340aecd6d3af508d8cf2a3c29456b00796c15813aab89052d257c8d8ab7a789b0077ca30795b39c237f438c4abd809c3dbe40cf92d82ba6c6d2af078e4a94861e55ee20fb436e35813bad0ced2603253b130174202471e8f277206b9c3a55e1ddbc9d85c8a30cd5dfc2f0e93694b7fc0f0e51009d47a71c629c2314bf9ff02b27cb0db97e2667decae1ba915196e444db8d4b963750bedcdea20253e5ccb2986dd4d0a59981bd9b037b509f14feb3d86b0814358522e604e09244acfd7edd1e395441e9786b11239fc105717af8bff55d5e1b0d279803fd3b3874d75e1f39e0aaffc070f53f73fc7692a1c332098fa38ef095283b73096d53a65fc18bd5aa4a4188c644dba3db9e95522388ac6f0f440ddb342456e5a6cfea86b28d48d098d155d550514827681c0648a05a2631e7dcadddd19a4daed928282091e04f2505a26e3ba16ce55404cb02f3bd16b8de538267e648ccb67c84c59a1732d34c654df1281e93882bdfe48bf146baad3da0b45103aad6652bf9a1d594d4d5c5f66af6d0e0c4c6477e57f43d0515c832a517f2408dfb8fbea234f039dd9dbe1a3d6e8bd987b9aaa95ced0bc9863df075411b3eba62a7c2b82384fa7a86d6fee603af766d4c9aa472c6b88e5b159344c1727c8e868659f744b4f6512766e9b7e4c37e7205ac249c9a989cbd1bf4a5d708694a17ccc662ffd5ff18be220cf01d599416ae01ed21caed0c09a51db9676271a3042c8e28156d147ba0d4cb1cf296c8caa1d88d8a8bb759fc5090d331dae4670a5e88d4e3f49d58c938163deab9e05ca370a0950123a2dc308154ad9edc74738fd3bf477ae273e54443ca4306dd205453991ab71039dc1ec98304cd14515662bf016fa34f0462003aff64dbf10ed0d4ae9624f2fcf61ce750cb4a2dcf0c8a4905a13dcd3f5e66a294ee52ff646a83654cf43b157cf5edb1387854cd817c37e41d93997276e90bcff474a493f6c814b314539161cd72b53a0c4d3bbaf3aed4e4f8d152b7738841836a6423f037ed038730cc431e5cdd4f9e3b9751fd2cabba13716730553fd2c30973535f783183cf895bb078c2e92b68d72281a1c8d87a5ae6eb4fee0dec1b776a17e09f5ce43467759362ec2b6673f642d3b68cc1cd510925fd97bfdcad99bb5104478ea4b002e2aefcee88167d0aaf1ea6ea898ca4c2ff71b9d722fc4064fc52c2c66c20770c9b0d5a44bafa1b0b503049a57679db52e9dd29a4d3d87fbe882a1b30982cb6979c093011a2cb0af9512df5a26bed5fbb8a6b367a3eaa1fa105931234d5cd62707ef7ebb7c8cf005af8e1585aafc441fdc4520c505bc80dec735dc48de0393782e15867482238efc75d92df029c847d1c29581740c47c78253b6c1224e677b8b105e92a71e24b6cc56564fd938302b64f79fcc1edb9a86c2915438f82f5e55c297fe749eff6730b8a6b9dd008c4f1e7d13a217de924f41a8ad6f8fd0bccd9ec47cc2674baf332dc27d4f994a0826ec7039ba49e35e6aa3d35c2d34bf647fb9c6bf19533fa16544950ac644cf12cd73b03d0f25c4f486a159fbbed37a6c288ad5599477e4e16c2bc67b76c904a1fbbe901f183e7bff64dbdbfddf984cf94b7b57afc21a16229e6db7bd1f9b64566856bb09a93cc95645d31c647cd5ac6fdeea9ed6038dadb3787c976858b92dfd982adcf6806fbab85e895df1ac666ef92708cc58e11d4f25d7aa72878721b4c19642c2b378e8b747f72ff3ac152d3059d4b3f5ac7405dd63c6109d2bde1b145267a0a5a25c529cd6fbc6b215ed9639455f1cdb4aba51d7c0aa0335a66eb541b0bfd24c4b9579c38529636137df5a37b846b906ed603dfc0158c863a5a4c54d439fab4875cc9871be4a3c6e9ac5d6e9f2940d3f836c76d672890212728425ea855f593a105c0257eaba9f4fe11186cdbb71124b5af6065f6e6c6554d1a9220e30a64983b07a14e5a5a5f6acabcdc39140bdc40f7cba7cccbacce73d0459d31d062fb2a3c9ef1b738b4115da70b5084f34f93a66a578dd1f71a4f83eceb2f9ab6cb50cc1dc95b3f4a058d456a2ffefa26581f40bfb8db0c65913cb8354da4dafa4efed03b09d147b7cced85eddfcb39107fe0d0f18e027aa4f1fb724160aac515f68395898c5a028d9d74e91e8ee5c0a247313deb35aec9b40f5ec9affab464688459781319117c6d7f351a6b3fb981b79ea472459a4d98ade65e99a171d4840e83cc015b15516cc86fb3b35a3fc351f55dc436bfe7bcadaac7becc8b6702093d4d08341e0f81a95509843dcc9aa33b6111c0b1be0e93eb0fc25d4a98531dabc27ed09d81306e8a6f08fe8636e247f055f57a0a2935e8918bc0dc1c443cab4e1ded33723e919e868d251c8b5e85273821c123b49432b239514a59e227a100db9df13d3e03aebf6a6858fe81f708eea47d933144b4187a7aab2a1536933c161f6ccd6fda3387d79b1d165cf0ffd6ccda8f64dc7c8aa280bcb90742afbcfacefc6fa4e0ff85ade61a9c08fff370e7690c6e1606814793607f3bd43c6d416e114d44ef866b4db73697e838d956789565b74536a4157b8dc83dc6eb1a52ea5690090541af335e909365a9571f0abfdb12c90d78e85782c29b95519090a6c973da5878d24152edad2c40dbfc3f2f839f600746df67c5b8f29b90ea2c4629536d7da121e75bd2df94a7b37da4c782718be92df8171eced4efbc9289903ea71082e1eb8a01a1d8858c2e3a1e5c7d22f1d45b31ab5fc762ad4c3fd1a3ba088076a559f1b580f551616308e785d699faba42870de4c0d752eaf425a353eda1d8b513070b8c545349c88db799533f973886d3f456562e4ddd28205c2486b175b9ee6ebd8358c9a645f4528839ea3bca1a063dce36ad23f06e8131620ff65d178fa7c7a871b764ac2b8716d74fcbae8dce9935cf9b0f4762bb6fe8661ef29469d7856e1d876dce87f686dc80c46cbffc9352e52d028ee1c3fc67827ddfa3c4c39633ca61cfb7959b8f921381e82cbd99964fadca48745b50ffbb2341d42b709b754d0159da3c359d36df86d225e7bb599ef21bebb1e0ab13d212cd713ec7edeb8ccba09b6ee33f922f6d4f90e08182d4fd4945f96cb7cce76bd0b8f62002ec33ccaa765e63ab10b8cdec743d8d02cc2427aa3e527080548f5948806e1a320a7d40cc3856079616a682ae989603c91980d7ffa10fa4521b87955a6f4c8b207fcb6a15fa1ebe77905d599d3d7ef9bd1ca34193525397cfef0629a3569234ad34ffa9ce49f500725049749fe64bee7936db540d8f0bc0891608ed98454ba58f616ac0d77c9ac9ab50216d11001821d3088f85920335de54313c25bf255668b635fc222d5042b5a2d6f130b7ea347cd0e5786339f0d3142babe8ec51a26f2c997b3124f52d19b6f364295b15c6968754c4086705f4eb2fb25421fd1e4e72496e3ffad51481f0dd1bb7a93ee22b2cbe89a8462a39628bc5296d9c06651449cd54c5da82c4d10693a9ec3e400c7c0a9bc1a6d76d1d68b32ae5ee46d47a7a8a5907903ac86b23651d68a3c17566acb7bca3c78c9b30fe2607eec1da72a870b7d8750b3653fb6b22567f688b009a4c9a8b6c93a0b66c782de3d1ddf1fb763cae90a4536fa97572a89944d1193a099c8c42e05d31fad68458f561447ed5bf60d534938b33fb9d1a0f216efa9f6de3ffb8c1273008fb8803d480c07a6ba056ab705842b736fa819e934c5f8295615fa45992b4c95be446fb0ca16ab9843a350e49c3d9864168702819fec1860ee2511d1050d4351a7a283d0a5af77664c7dcbe9187e1e02dd8ae32b57c2d1c5e7048cf044ee29baa7ec7b85675c74ca15c5e9b239a7a4a6f1f09b3e18f8e83181c810f997f385a675c6b52dc2ec0fdbe7bec4f2a497e8663b9ac7fdb03d314d70ac583a92eb34ae7a3c923d53dd6bb7ddd09ed31f2145c3bccdf64e07d184c27408e4833c046c50973d37a17652fd582315cfc6b87646ba1c4e4b958d4b7a6dd353f8cd22de3245bd968bf5cca437e0da2f622a46fc24b3cdd9ab71504630883b806d215d583943c6e1b68c65d5bf1672249085038939697ea1c2c2ee191a030d8bab81ed7172999ac047573ed8bf710ac64b560c92587b037651a54c848d990afd32334662007af8775731736199a520cd6c78421309addae88d5283c79057dd36226996e3f858493356c652ea909ec77315d37a07b2f6e36ff645335238764ff525a96906770f68429728338a8e577fbd616cbd7ad5d2436f91b2794d099dfc97363440f1f182b93f5815f458774776380f348cf79440054b1066f36123603bae788627167c3c85aa25c75179c02e0df7576ea5e3176244f831901d4c6ba7a50a7526cfd5dfdd69e478e8002b57562564147821fd29e434181d5ab52937633967010ea059126c66926c2d19535edf8e5c42e8f5343f6fd6c2ce032ad521141da51581655a329c535b52dc59d1eecb309456b43532653f2452a8c9a03fe1938492b9a1ceb279b43d58bbf9cdf224b7e5fa624aa1bab579967cd7d5ac1f8f49dbb2887230efafa5d73832429eb1981a73eb88b092a7a3507d35332c5594c07e39475515cedd506132443a1415f0c1ca01d2f492670b3afabc0a5667cced3362714b30683afcafa164ec7d8e55a51c9f36c0831e288b3aa32559851d90b2acd837c9128fa50d53558d48564c3f24056145b9bd09db01c403efb256c18ffb71b1e89a131253d14e4c50a543c62475fd2c416d5b955b86e4be59f1d82f43e384e417dad9b4077a2208d27ba92a3866fbb9fe9783e60b96ee95e2dd06f4dfc09843bdf3a4f46c320552fe497e838f377078d288c5f314b3dce9dcc01d09819a5157d2b045efa00e6408e8322b22c5a598bc167245ca765610f8324bc1a707f81381cafeba26c2bde334bf4025624f303f7aed77f57190721e6b360fe9a2ac93b94420666641a906e321f20872fcac2f541a76a868139b09e5d5b4f464ef5227660b74ec5c747b782f95f0b443066356bb22b733093dc1580eb95b6aef63fadb23614458a8ca08689ab2643f099e966431e88d29cf5c88c48c509678a4d6ca8aa5dc83a4c4b28eb89b01c562eca7c989e7f8e4e3d7469e2f0d86bd9aa1820d8ca6cea9da3a9f73abbfe936cc8841a76a86a22294d7e93e2e086cbdd47b0c2524e527c381d75d333ccd672a22751bd9a4f51265a5d27a312b341adc4b66e29ed56e5d6b7fab73a1435a395bfba2ef86aa53ce377132ae5af6974124285e603676900709daf3b16abac1a7f1aa888452365d7fd71cf7dc4e7f2c79a4c93adb04e63c2bdc28a74cfb9e43afc821e0ea1fbb185e0d4b80cdb08151688f1fa392557bace8150825fa939cc6358fd8797fa5e2b6d679443c0f47f8c3f34df9c15bbc77f3c6ab1dab4f16d22573000d0a0070686173653e20646573796e6368726f6e697a6564000000000070686173653e2073796e6368726f6e697a6174696f6e206163686965766564000000000000000000"
XMMWORD_53E0_HEX = "010000000000000078563412f0debc9a"
XMMWORD_53F0_HEX = "275941314eb28262750bc4939c6405c5"
XMMWORD_5400_HEX = "c3bd46f6ea1688271170c95838c90a8a"      # 16 bytes -> 32 hex chars
 
 
def load_tables():
    byte_20c0 = bytes.fromhex(BYTE_20C0_HEX)
    dword_27e0_raw = bytes.fromhex(DWORD_27E0_HEX)
    len_table_raw = bytes.fromhex(LEN_TABLE_HEX)
    off_table_raw = bytes.fromhex(OFFSET_TABLE_HEX)
    unk_2bc0 = bytes.fromhex(UNK_2BC0_HEX)
    xmm_53e0 = bytes.fromhex(XMMWORD_53E0_HEX)
    xmm_53f0 = bytes.fromhex(XMMWORD_53F0_HEX)
    xmm_5400 = bytes.fromhex(XMMWORD_5400_HEX)
 
    dword_27e0 = list(struct.unpack("<116I", dword_27e0_raw))
    len_table = list(struct.unpack("<116H", len_table_raw))
    off_table = list(struct.unpack("<116H", off_table_raw))

    return {
        "byte_20c0": byte_20c0,
        "dword_27e0": dword_27e0,
        "len_table": len_table,
        "off_table": off_table,
        "unk_2bc0": unk_2bc0,
        "regs_init": list(struct.unpack("<4I", xmm_53e0)),
        "seed_a": list(struct.unpack("<4I", xmm_53f0)),
        "seed_b": list(struct.unpack("<4I", xmm_5400)),
    }


# Core primitive: xorshift32 with the (13, 17, 5) triple used everywhere
# in this binary (both scalar and, for the sub-VM register seeding, SIMD
# per-lane).
def xorshift32(x: int) -> int:
    x &= MASK32
    x ^= (x << 13) & MASK32
    x ^= (x >> 17)
    x ^= (x << 5) & MASK32
    return x & MASK32


def rol32(x: int, n: int) -> int:
    n &= 31
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32 if n else x


def ror32(x: int, n: int) -> int:
    n &= 31
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32 if n else x



# Step 1: decrypt the main 1824-byte bytecode blob (-> 228 instructions)
def decode_main_bytecode(byte_20c0: bytes) -> bytes:
    out = bytearray(1824)
    state = 2067430356
    v6 = 97
    for i in range(1824):
        pre = (state + 3 * i - 1515870811) & MASK32
        state = xorshift32(pre)
        v8 = (state >> (8 * (i & 3))) & 0xFF
        v9 = byte_20c0[i]
        v10 = (v6 ^ v9) & 0xFF
        v6 = (v6 + 29) & 0xFF
        out[i] = (v8 ^ v10) & 0xFF
    return bytes(out)


def decode_subprogram(call_idx: int, tables) -> bytes:
    off = tables["off_table"][call_idx]
    length = tables["len_table"][call_idx]

    if length == 0:
        return b""

    seed = (
        rol32(2072009247, (7 * call_idx) % 31)
        ^ tables["dword_27e0"][call_idx]
        ^ ((-1640531527 * (call_idx + 1)) & MASK32)
        ^ ((73244475 * (call_idx + 1)) & MASK32)
    )

    src = tables["unk_2bc0"][off: off + length]
    out = bytearray(length)
    state = seed
    v22 = (-125 * call_idx) & 0xFF

    for i in range(length):
        pre = (state + 17 * call_idx + 2135587861 + i) & MASK32
        state = xorshift32(pre)
        v26 = (v22 ^ src[i]) & 0xFF
        v22 = (v22 + 17) & 0xFF
        out[i] = ((state >> (8 * (i & 3))) ^ v26) & 0xFF

    return bytes(out)



# Sub-VM (the "phase" bytecode invoked by outer opcode 0xCD)
def run_subprogram(code: bytes, input_bytes: bytes, call_idx: int, outer_reg2_val: int, anti_debug_flag: int) -> bool:
    v28 = (call_idx ^ outer_reg2_val ^ anti_debug_flag) & MASK32
    lane_seed = (v28 + call_idx) & MASK32
    regs = [0] * 8

    for lane in range(4):
        v29 = lane_seed     # Same value every lane
        va = (v29 + SEED_A[lane]) & MASK32
        x = va ^ ((va << 13) & MASK32)
        x ^= (x >> 17)
        regs[lane] = (x ^ ((x << 5) & MASK32)) & MASK32

        vb = (v29 + SEED_B[lane]) & MASK32
        y = vb ^ ((vb << 13) & MASK32)
        y ^= (y >> 17)
        regs[4 + lane] = (y ^ ((y << 5) & MASK32)) & MASK32

    n_instr = len(code) // 8
    input_len = len(input_bytes)

    for i in range(n_instr):
        b = code[i * 8: i * 8 + 8]
        op = b[0]
        r1 = b[1] & 7
        r2 = b[2] & 7
        r3 = b[3] & 7   # Also used as raw shift count for opcode 0x59
        imm = b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)

        if op == 0x71:  # 'q' ROL by reg
            regs[r1] = rol32(regs[r1], r2)
        elif op > 0x71:
            if op == 0xA7:
                regs[r1] = ror32(regs[r1], r2)
            elif op > 0xA7:
                if op == 0xAB:
                    regs[r1] ^= imm
                    regs[r1] &= MASK32
                elif op == 0xD2:
                    regs[r1] = (regs[r1] * (imm | 1)) & MASK32
                else:
                    return False  # Invalid opcode -> fail
            else:
                if op == 0x7D:
                    if imm != regs[r1]:
                        return False
                elif op == 0x93:
                    regs[r1] = (regs[r1] - imm) & MASK32
                elif op == 0x76:
                    t = (imm + v28 + regs[r1] + regs[r2]) & MASK32
                    regs[r1] = xorshift32(t)
                else:
                    return False
        else:
            if op <= 0x30:
                if op <= 9:
                    return False  # Falls through to fail
                if op == 0x0A:
                    regs[r1] = imm
                elif op == 0x0F:
                    regs[r1] = (regs[r1] + imm) & MASK32
                elif op == 0x21:
                    return True     # <-- The ONLY success exit
                elif op == 0x26:
                    regs[r1] ^= regs[r3] ^ regs[r2] ^ imm
                    regs[r1] &= MASK32
                elif op == 0x30:
                    if imm >= input_len:
                        return False
                    regs[r1] = input_bytes[imm]
                else:
                    return False
            else:
                if op != 0x59:
                    return False
                t = (regs[r1] + regs[r2] + imm) & MASK32
                regs[r1] = rol32(t, b[3])

    return False    # Ran off the end without hitting 0x21 -> fail


# Populated by run_main() before calling run_subprogram()
SEED_A = [0, 0, 0, 0]
SEED_B = [0, 0, 0, 0]


# NOTE: This is the outer VM
def input_hash(a1: bytes, a2: int, seed_mix: int) -> int:
    v43 = (a2 ^ seed_mix ^ 0x846CA68B) & MASK32

    if a2 != 0:
        v45 = 0
        v47 = v43
        n = 0

        for b in a1:
            n += 1
            v49 = (v45 + b) & MASK32
            v45 = (v45 + 40503) & MASK32
            t = (v47 + v49) & MASK32
            t = t ^ ((t << 13) & MASK32)
            t ^= (t >> 17)
            v47 = (t ^ ((t << 5) & MASK32)) & MASK32

            if n >= a2 or n == 32:
                break

        v43 = v47

    return v43


# Run the decoded 1824-byte main program against `input_bytes`.
# Returns True/False or None if it ran off the end
# of the program without ever hitting the 0xA3 'return' opcode.
def run_main(code: bytes, input_bytes: bytes, tables, anti_debug_flag: int = 0, trace: bool = False) -> bool | None:
    global SEED_A, SEED_B
    SEED_A = tables["seed_a"]
    SEED_B = tables["seed_b"]

    regs = list(tables["regs_init"])
    a2 = len(input_bytes)
    n_instr = len(code) // 8

    for i in range(n_instr):
        b = code[i * 8: i * 8 + 8]
        op = b[0]
        r1 = b[1] & 7
        r2 = b[2] & 7
        imm = b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)

        if trace:
            print(f"[{i:3d}] op={op:#04x} r1={r1} r2={r2} imm={imm:#010x} regs={regs}")

        if op == 0xBF:
            regs[r1 & 3] = imm
        elif op > 0xBF:
            if op == 0xDC:
                h = input_hash(input_bytes, a2, imm)
                regs[r1 & 3] ^= (h >> 31) & 1
            elif op == 0xEF:
                regs[r1 & 3] = 1 if imm == a2 else 0
            elif op == 0xCD:
                if imm > 0x73:
                    return False
                sub_code = decode_subprogram(imm, tables)
                ok = run_subprogram(sub_code, input_bytes, imm, regs[r2 & 3], anti_debug_flag)
                regs[r1 & 3] = 1 if ok else 0
            else:
                return False
        else:
            if op == 0xA3:
                return bool(regs[r1 & 3] & 1)
            elif op > 0xA3:
                if op != 0xB7:
                    return False
                t = (imm + regs[r1 & 3] + regs[r2 & 3]) & MASK32
                t = t ^ ((t << 13) & MASK32)
                t ^= (t >> 17)
                regs[r1 & 3] = (t ^ ((t << 5) & MASK32)) & MASK32
            elif op == 0x91:
                regs[r1 & 3] = 1 if (regs[r2 & 3] & regs[r1 & 3]) != 0 else 0
            elif op == 0x95:
                t = (imm + anti_debug_flag + (regs[r2 & 3] ^ regs[r1 & 3])) & MASK32
                regs[r1 & 3] = rol32(t, b[3])
            else:
                return False

    return None  # Fell off the end (the binary treats this as reject)


# Generic brute-force:
#   1. run_main(..., trace=True) once on a dummy string to see the sequence
#      of 0xEF (length-check) / 0xCD (phase-call) instructions,
#   2. read off the required length from an 0xEF immediate,
#   3. brute-force per phase: since sub-VM phases typically pull in a
#      specific byte (opcode 0x30 with a fixed imm index) and only check
#      that byte (or a small combination) via 0x7D, we can recover each
#      character independently instead of brute-forcing the whole
#      string at once. This means we'll brute 256 bytes instead of 256^48
def brute_force(length: int, charset: str = None, tables=None):
    if charset is None:
        charset = "".join(chr(c) for c in range(0x20, 0x7F))  # printable ASCII

    if tables is None:
        tables = load_tables()

    main_code = decode_main_bytecode(tables["byte_20c0"])

    for combo in itertools.product(charset, repeat=length):
        cand = "".join(combo)

        if run_main(main_code, cand.encode(), tables, anti_debug_flag=0):
            return cand

    return None


# Return the ordered list of (instr_index, call_idx) for every 0xCD
# (phase-call) instruction in the decoded main program.
def parse_main_calls(code: bytes):
    calls = []
    n_instr = len(code) // 8

    for i in range(n_instr):
        b = code[i * 8: i * 8 + 8]
        if b[0] == 0xCD:
            imm = b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)
            calls.append(imm)

    return calls


def byte_reads(sub_code: bytes):
    idxs = set()
    n_instr = len(sub_code) // 8

    for i in range(n_instr):
        b = sub_code[i * 8: i * 8 + 8]
        if b[0] == 0x30:
            imm = b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)
            idxs.add(imm)
    
    return idxs


# Locate the 0xEF (length-check) instruction and read off the
# required input length directly, instead of guessing
def find_flag_length(main_code: bytes, tables) -> int:
    n_instr = len(main_code) // 8

    for i in range(n_instr):
        b = main_code[i * 8: i * 8 + 8]
        if b[0] == 0xEF:
            return b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)
    
    raise RuntimeError("no 0xEF length-check instruction found")


# We leverage the fact that each phase only reads a small and known set
# of fixed byte offsets from the input. We'll go through the phases in the
# order the outer VM calls them, bruteforcing only the not-yet-determined
# byte(s) each phase introduces, assuming the accumulator stays 1
def incremental_solve(tables=None, charset=range(0x20, 0x7F)):
    global SEED_A, SEED_B

    if tables is None:
        tables = load_tables()
    
    SEED_A = tables["seed_a"]
    SEED_B = tables["seed_b"]

    main_code = decode_main_bytecode(tables["byte_20c0"])
    length = find_flag_length(main_code, tables)
    calls = parse_main_calls(main_code)
    print(f"[*] required length = {length}, phase calls = {len(calls)}")

    known = bytearray(length)
    solved = [False] * length

    for call_idx in calls:
        sub_code = decode_subprogram(call_idx, tables)
        reads = sorted(x for x in byte_reads(sub_code) if x < length)
        unknown = [x for x in reads if not solved[x]]

        if not unknown:
            ok = run_subprogram(sub_code, bytes(known), call_idx, 1, 0)
            if not ok:
                print(f"[!] phase {call_idx}: no new bytes, but FAILS with "
                      f"current guess - a previously 'solved' byte must be "
                      f"wrong (collision). Reads={reads}")
            continue

        found = None
        for combo in itertools.product(charset, repeat=len(unknown)):
            trial = bytearray(known)
            for idx, val in zip(unknown, combo):
                trial[idx] = val
            if run_subprogram(sub_code, bytes(trial), call_idx, 1, 0):
                found = combo
                break

        if found is None:
            print(f"[!] phase {call_idx}: could not solve new byte(s) "
                  f"{unknown} within charset - widen charset or check "
                  f"table extraction. reads={reads}")
            continue

        for idx, val in zip(unknown, found):
            known[idx] = val
            solved[idx] = True

        shown = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in known)
        print(f"Flag: {shown}", end="\r")

    return bytes(known), all(solved)


if __name__ == "__main__":
    tabs = load_tables()
    flag, complete = incremental_solve(tables=tabs)

    if complete:
        print("FLAG:", flag.decode(errors="replace"))
    else:
        print("Could not fully solve - partial result:", flag)
        print("(see [!] warnings above for which phase(s) got stuck)")
