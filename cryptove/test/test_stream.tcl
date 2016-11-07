#===============================================================================
# stream test case for TCL
#
# stream test
#
# Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
# functions:
# test_rc4
# test_chacha20_poly1305
#===============================================================================
#

source [file join [file dirname [info script]] ../cryptove.tcl]

# RFC 6229 test vectors
set rc4_test_case {
	case1 {
		key         "0102030405"
		stream1     "b2396305f03dc027ccc3524a0a1118a86982944f18fc82d589c403a47a0d0919"
		stream240   "28cb1132c96ce286421dcaadb8b69eae1cfcf62b03eddb641d77dfcf7f8d8c93"
		stream496   "42b7d0cdd918a8a33dd51781c81f40416459844432a7da923cfb3eb4980661f6"
		stream752   "ec10327bde2beefd18f9277680457e22eb62638d4f0ba1fe9fca20e05bf8ff2b"
		stream1008  "45129048e6a0ed0b56b490338f078da530abbcc7c20b01609f23ee2d5f6bb7df"
		stream1520  "3294f744d8f9790507e70f62e5bbceead8729db41882259bee4f825325f5a130"
		stream2032  "1eb14a0c13b3bf47fa2a0ba93ad45b8bcc582f8ba9f265e2b1be9112e975d2d7"
		stream3056  "f2e30f9bd102ecbf75aaade9bc35c43cec0e11c479dc329dc8da7968fe965681"
		stream4080  "068326a2118416d21f9d04b2cd1ca050ff25b58995996707e51fbdf08b34d875"
	}
	case2 {
		key          "01020304050607"
		stream1      "293f02d47f37c9b633f2af5285feb46be620f1390d19bd84e2e0fd752031afc1"
		stream240    "914f02531c9218810df60f67e338154cd0fdb583073ce85ab83917740ec011d5"
		stream496    "75f81411e871cffa70b90c74c592e4540bb87202938dad609e87a5a1b079e5e4"
		stream752    "c2911246b612e7e7b903dfeda1dad86632828f91502b6291368de8081de36fc2"
		stream1008   "f3b9a7e3b297bf9ad804512f9063eff18ecb67a9ba1f55a5a067e2b026a3676f"
		stream1520   "d2aa902bd42d0d7cfd340cd45810529f78b272c96e42eab4c60bd914e39d06e3"
		stream2032   "f4332fd31a079396ee3cee3f2a4ff04905459781d41fda7f30c1be7e1246c623"
		stream3056   "adfd3868b8e51485d5e610017e3dd609ad26581c0c5be45f4cea01db2f3805d5"
		stream4080   "f3172ceffc3b3d997c85ccd5af1a950ce74b0b9731227fd37c0ec08a47ddd8b8"
	}
	case3 {
		key          "0102030405060708"
		stream1      "97ab8a1bf0afb96132f2f67258da15a88263efdb45c4a18684ef87e6b19e5b09"
		stream240    "9636ebc9841926f4f7d1f362bddf6e18d0a990ff2c05fef5b90373c9ff4b870a"
		stream496    "73239f1db7f41d80b643c0c52518ec63163b319923a6bdb4527c626126703c0f"
		stream752    "49d6c8af0f97144a87df21d91472f96644173a103b6616c5d5ad1cee40c863d0"
		stream1008   "273c9c4b27f322e4e716ef53a47de7a4c6d0e7b226259fa9023490b26167ad1d"
		stream1520   "1fe8986713f07c3d9ae1c163ff8cf9d38369e1a965610be887fbd0c79162aafb"
		stream2032   "0a0127abb44484b9fbef5abcae1b579fc2cdadc6402e8ee866e1f37bdb47e42c"
		stream3056   "26b51ea37df8e1d6f76fc3b66a7429b3bc7683205d4f443dc1f29dda3315c87b"
		stream4080   "d5fa5a3469d29aaaf83d23589db8c85b3fb46e2c8f0f068edce8cdcd7dfc5862"
	}
	case4 {
		key          "0102030405060708090a"
		stream1      "ede3b04643e586cc907dc2185170990203516ba78f413beb223aa5d4d2df6711"
		stream240    "3cfd6cb58ee0fdde640176ad0000044d48532b21fb6079c9114c0ffd9c04a1ad"
		stream496    "3e8cea98017109979084b1ef92f99d86e20fb49bdb337ee48b8d8dc0f4afeffe"
		stream752    "5c2521eacd7966f15e056544bea0d315e067a7031931a246a6c3875d2f678acb"
		stream1008   "a64f70af88ae56b6f87581c0e23e6b08f449031de312814ec6f319291f4a0516"
		stream1520   "bdae85924b3cb1d0a2e33a30c6d795998a0feddbac865a09bcd127fb562ed60a"
		stream2032   "b55a0a5b51a12a8be34899c3e047511ad9a09cea3ce75fe39698070317a71339"
		stream3056   "552225ed1177f44584ac8cfa6c4eb5fc7e82cbabfc95381b080998442129c2f8"
		stream4080   "1f135ed14ce60a91369d2322bef25e3c08b6be45124a43e2eb77953f84dc8553"
	}
	case5 {
		key          "0102030405060708090a0b0c0d0e0f10"
		stream1      "9ac7cc9a609d1ef7b2932899cde41b975248c4959014126a6e8a84f11d1a9e1c"
		stream240    "065902e4b620f6cc36c8589f66432f2bd39d566bc6bce3010768151549f3873f"
		stream496    "b6d1e6c4a5e4771cad79538df295fb11c68c1d5c559a974123df1dbc52a43b89"
		stream752    "c5ecf88de897fd57fed301701b82a259eccbe13de1fcc91c11a0b26c0bc8fa4d"
		stream1008   "e7a72574f8782ae26aabcf9ebcd66065bdf0324e6083dcc6d3cedd3ca8c53c16"
		stream1520   "b40110c4190b5622a96116b0017ed297ffa0b514647ec04f6306b892ae661181"
		stream2032   "d03d1bc03cd33d70dff9fa5d71963ebd8a44126411eaa78bd51e8d87a8879bf5"
		stream3056   "fabeb76028ade2d0e48722e46c4615a3c05d88abd50357f935a63c59ee537623"
		stream4080   "ff38265c1642c1abe8d3c2fe5e572bf8a36a4c301ae8ac13610ccbc12256cacc"
	}
	case6 {
		key          "0102030405060708090a0b0c0d0e0f101112131415161718"
		stream1      "0595e57fe5f0bb3c706edac8a4b2db11dfde31344a1af769c74f070aee9e2326"
		stream240    "b06b9b1e195d13d8f4a7995c4553ac056bd2378ec341c9a42f37ba79f88a32ff"
		stream496    "e70bce1df7645adb5d2c4130215c35229a5730c7fcb4c9af51ffda89c7f1ad22"
		stream752    "0485055fd4f6f0d963ef5ab9a5476982591fc66bcda10e452b03d4551f6b62ac"
		stream1008   "2753cc83988afa3e1688a1d3b42c9a0293610d523d1d3f0062b3c2a3bbc7c7f0"
		stream1520   "96c248610aadedfeaf8978c03de8205a0e317b3d1c73b9e9a4688f296d133a19"
		stream2032   "bdf0e6c3cca5b5b9d533b69c56ada12088a218b6e2ece1e6246d44c759d19b10"
		stream3056   "6866397e95c140534f94263421006e4032cb0a1e9542c6b3b8b398abc3b0f1d5"
		stream4080   "29a0b8aed54a132324c62e423f54b4c83cb0f3b5020a98b82af9fe154484a168"
	}
	case7 {
		key          "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
		stream1      "eaa6bd25880bf93d3f5d1e4ca2611d91cfa45c9f7e714b54bdfa80027cb14380"
		stream240    "114ae344ded71b35f2e60febad727fd802e1e7056b0f623900496422943e97b6"
		stream496    "91cb93c787964e10d9527d999c6f936b49b18b42f8e8367cbeb5ef104ba1c7cd"
		stream752    "87084b3ba700bade955610672745b374e7a7b9e9ec540d5ff43bdb12792d1b35"
		stream1008   "c799b596738f6b018c76c74b1759bd907fec5bfd9f9b89ce6548309092d7e958"
		stream1520   "40f250b26d1f096a4afd4c340a5888153e34135c79db010200767651cf263073"
		stream2032   "f656abccf88dd827027b2ce917d464ec18b62503bfbc077fbabb98f20d98ab34"
		stream3056   "8aed95ee5b0dcbfbef4eb21d3a3f52f9625a1ab00ee39a5327346bddb01a9c18"
		stream4080   "a13a7c79c7e119b5ab0296ab28c300b9f3e4c0a2e02d1d01f7f0a74618af2b48"
	}
	case8 {
		key          "833222772a"
		stream1      "80ad97bdc973df8a2e879e92a497efda20f060c2f2e5126501d3d4fea10d5fc0"
		stream240    "faa148e99046181fec6b2085f3b20ed9f0daf5bab3d596839857846f73fbfe5a"
		stream496    "1c7e2fc4639232fe297584b296996bc83db9b249406cc8edffac55ccd322ba12"
		stream752    "e4f9f7e0066154bbd125b745569bc89775d5ef262b44c41a9cf63ae14568e1b9"
		stream1008   "6da453dbf81e82334a3d8866cb50a1e37828d074119cab5c22b294d7a9bfa0bb"
		stream1520   "adb89cea9a15fbe617295bd04b8ca05c6251d87fd4aaae9a7e4ad5c217d3f300"
		stream2032   "e7119bd6dd9b22afe8f89585432881e2785b60fd7ec4e9fcb6545f350d660fab"
		stream3056   "afecc037fdb7b0838eb3d70bcd268382dbc1a7b49d57358cc9fa6d61d73b7cf0"
		stream4080   "6349d126a37afcba89794f9804914fdcbf42c3018c2f7c66bfde524975768115"
	}
	case9 {
		key          "1910833222772a"
		stream1      "bc9222dbd3274d8fc66d14ccbda6690b7ae627410c9a2be693df5bb7485a63e3"
		stream240    "3f0931aa03defb300f060103826f2a64beaa9ec8d59bb68129f3027c96361181"
		stream496    "74e04db46d28648d7dee8a0064b06cfe9b5e81c62fe023c55be42f87bbf932b8"
		stream752    "ce178fc1826efecbc182f57999a461408bdf55cd55061c06dba6be11de4a578a"
		stream1008   "626f5f4dce652501f3087d39c92cc34942daac6a8f9ab9a7fd137c6037825682"
		stream1520   "cc03fdb79192a207312f53f5d4dc33d9f70f14122a1c98a3155d28b8a0a8a41d"
		stream2032   "2a3a307ab2708a9c00fe0b42f9c2d6a1862617627d2261eab0b1246597ca0ae9"
		stream3056   "55f877ce4f2e1ddbbf8e13e2cde0fdc81b1556cb935f173337705fbb5d501fc1"
		stream4080   "ecd0e96602be7f8d5092816cccf2c2e9027881fab4993a1c262024a94fff3f61"
	}
	case10 {
		key          "641910833222772a"
		stream1      "bbf609de9413172d07660cb68071692646101a6dab43115d6c522b4fe93604a9"
		stream240    "cbe1fff21c96f3eef61e8fe0542cbdf0347938bffa4009c512cfb4034b0dd1a7"
		stream496    "7867a786d00a7147904d76ddf1e520e38d3e9e1caefcccb3fbf8d18f64120b32"
		stream752    "942337f8fd76f0fae8c52d7954810672b8548c10f51667f6e60e182fa19b30f7"
		stream1008   "0211c7c6190c9efd1237c34c8f2e06c4bda64f65276d2aacb8f90212203a808e"
		stream1520   "bd3820f732ffb53ec193e79d33e27c73d0168616861907d482e36cdac8cf5749"
		stream2032   "97b0f0f224b2d2317114808fb03af7a0e59616e469787939a063ceea9af956d1"
		stream3056   "c47e0dc1660919c11101208f9e69aa1f5ae4f12896b8379a2aad89b5b553d6b0"
		stream4080   "6b6b098d0c293bc2993d80bf0518b6d98170cc3ccd92a698621b939dd38fe7b9"
	}
	case11 {
		key          "8b37641910833222772a"
		stream1      "ab65c26eddb287600db2fda10d1e605cbb759010c29658f2c72d93a2d16d2930"
		stream240    "b901e8036ed1c383cd3c4c4dd0a6ab053d25ce4922924c55f064943353d78a6c"
		stream496    "12c1aa44bbf87e75e611f69b2c38f49b28f2b3434b65c09877470044c6ea170d"
		stream752    "bd9ef822de5288196134cf8af783930467559c23f052158470a296f725735a32"
		stream1008   "8bab26fbc2c12b0f13e2ab185eabf24131185a6d696f0cfa9b42808b38e132a2"
		stream1520   "564d3dae183c5234c8af1e51061c44b53c0778a7b5f72d3c23a3135c7d67b9f4"
		stream2032   "f34369890fcf16fb517dcaae4463b2dd02f31c81e8200731b899b028e791bfa7"
		stream3056   "72da646283228c14300853701795616f4e0a8c6f7934a788e2265e81d6d0c8f4"
		stream4080   "438dd5eafea0111b6f36b4b938da2a685f6bfc73815874d97100f086979357d8"
	}
	case12 {
		key           "ebb46227c6cc8b37641910833222772a"
		stream1       "720c94b63edf44e131d950ca211a5a30c366fdeacf9ca80436be7c358424d20b"
		stream240     "b3394a40aabf75cba42282ef25a0059f4847d81da4942dbc249defc48c922b9f"
		stream496     "08128c469f275342adda202b2b58da95970dacef40ad98723bac5d6955b81761"
		stream752     "3cb89993b07b0ced93de13d2a11013acef2d676f1545c2c13dc680a02f4adbfe"
		stream1008    "b60595514f24bc9fe522a6cad7393644b515a8c5011754f59003058bdb81514e"
		stream1520    "3c70047e8cbc038e3b9820db601da4951175da6ee756de46a53e2b075660b770"
		stream2032    "00a542bba02111cc2c65b38ebdba587e5865fdbb5b48064104e830b380f2aede"
		stream3056    "34b21ad2ad44e999db2d7f0863f0d9b684a9218fc36e8a5f2ccfbeae53a27d25"
		stream4080    "a2221a11b833ccb498a59540f0545f4a5bbeb4787d59e5373fdbea6c6f75c29b"
	}
	case13 {
		key           "c109163908ebe51debb46227c6cc8b37641910833222772a"
		stream1       "54b64e6b5a20b5e2ec84593dc7989da7c135eee237a85465ff97dc03924f45ce"
		stream240     "cfcc922fb4a14ab45d6175aabbf2d201837b87e2a446ad0ef798acd02b94124f"
		stream496     "17a6dbd664926a0636b3f4c37a4f46944a5f9f26aeeed4d4a25f632d305233d9"
		stream752     "80a3d01ef00c8e9a4209c17f4eeb358cd15e7d5ffaaabc0207bf200a117793a2"
		stream1008    "349682bf588eaa52d0aa1560346aeafaf5854cdb76c889e3ad63354e5f7275e3"
		stream1520    "532c7ceccb39df3236318405a4b1279cbaefe6d9ceb651842260e0d1e05e3b90"
		stream2032    "e82d8c6db54e3c633f581c952ba042074b16e50abd381bd70900a9cd9a62cb23"
		stream3056    "3682ee33bd148bd9f58656cd8f30d9fb1e5a0b8475045d9b20b2628624edfd9e"
		stream4080    "63edd684fb826282fe528f9c0e9237bce4dd2e98d6960fae0b43545456743391"
	}
	case14 {
		key           "1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a"
		stream1       "dd5bcb0018e922d494759d7c395d02d3c8446f8f77abf737685353eb89a1c9eb"
		stream240     "af3e30f9c095045938151575c3fb9098f8cb6274db99b80b1d2012a98ed48f0e"
		stream496     "25c3005a1cb85de076259839ab7198ab9dcbc183e8cb994b727b75be3180769c"
		stream752     "a1d3078dfa9169503ed9d4491dee4eb28514a5495858096f596e4bcd66b10665"
		stream1008    "5f40d59ec1b03b33738efa60b2255d313477c7f764a41baceff90bf14f92b7cc"
		stream1520    "ac4e95368d99b9eb78b8da8f81ffa7958c3c13f8c2388bb73f38576e65b7c446"
		stream2032    "13c4b9c1dfb66579eddd8a280b9f7316ddd27820550126698efaadc64b64f66e"
		stream3056    "f08f2e66d28ed143f3a237cf9de735599ea36c525531b880ba124334f57b0b70"
		stream4080    "d5a39e3dfcc50280bac4a6b5aa0dca7d370b1c1fe655916d97fd0d47ca1d72b8"
	}
}

proc test_rc4 {} {
	global rc4_test_case
	set msg [string repeat 00 5000]
	for {set i 1} {$i <= 14} {incr i 1} {
		puts case-$i
		set case [dict get $rc4_test_case case$i]
		set k [dict get $case key]
		set res_stream1     [dict get $case stream1   ]
		set res_stream240 	[dict get $case stream240 ]
		set res_stream496 	[dict get $case stream496 ]
		set res_stream752 	[dict get $case stream752 ]
		set res_stream1008	[dict get $case stream1008]
		set res_stream1520	[dict get $case stream1520]
		set res_stream2032	[dict get $case stream2032]
		set res_stream3056	[dict get $case stream3056]
		set res_stream4080	[dict get $case stream4080]
		set res [rc4_enc $k $msg]
        puts stream1
		if {[cmp [string range $res 0 63] $res_stream1]} {
			puts res_[string range $res 0 63]
			puts res_$res_stream1
			return -code error "rc4 test case$i stream1 error!"
		}
        puts stream240
		if {[cmp [string range $res 480 543] $res_stream240]} {
			puts res_[string range $res 480 543]
			puts res_$res_stream240
			return -code error "rc4 test case$i stream240 error!"
		}
        puts stream496
		if {[cmp [string range $res 992 1055] $res_stream496]} {
			puts res_[string range $res 992 1055]
			puts res_$res_stream496
			return -code error "rc4 test case$i stream496 error!"
		}
        puts stream752
		if {[cmp [string range $res 1504 1567] $res_stream752]} {
			puts res_[string range $res 1504 1567]
			puts res_$res_stream752
			return -code error "rc4 test case$i stream752 error!"
		}
        puts stream1008
		if {[cmp [string range $res 2016 2079] $res_stream1008]} {
			puts res_[string range $res 2016 2079]
			puts res_$res_stream1008
			return -code error "rc4 test case$i stream1008 error!"
		}
        puts stream1520
		if {[cmp [string range $res 3040 3103] $res_stream1520]} {
			puts res_[string range $res 3040 3103]
			puts res_$res_stream1520
			return -code error "rc4 test case$i stream1520 error!"
		}
        puts stream2032
		if {[cmp [string range $res 4064 4127] $res_stream2032]} {
			puts res_[string range $res 4064 4127]
			puts res_$res_stream2032
			return -code error "rc4 test case$i stream2032 error!"
		}
        puts stream3056
		if {[cmp [string range $res 6112 6175] $res_stream3056]} {
			puts res_[string range $res 6112 6175]
			puts res_$res_stream3056
			return -code error "rc4 test case$i stream3056 error!"
		}
        puts stream4080
		if {[cmp [string range $res 8160 8223] $res_stream4080]} {
			puts res_[string range $res 8160 8223]
			puts res_$res_stream4080
			return -code error "rc4 test case$i stream4080 error!"
		}
	}
}



proc test_chacha20_poly1305 {} {
	set key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
	set nonce 000000090000004a00000000
	set counter 00000001
	set std 10F1E7E4D13B5915500FDD1FA32071C4C7D1F4C733C068030422AA9AC3D46C4ED2826446079FAA0914C2D705D98B02A2B5129CD1DE164EB9CBD083E8A2503C4E

	set res  [chacha20_block $key $counter $nonce]
	if {[cmp $res $std]} {
		puts std_$std
		puts res_$res
		return -code error "chacha20_block error"
	}

	set msg 43727970746f6772617068696320466f72756d2052657365617263682047726f7570
	set key 85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b
	set std a8061dc1305136c6c22b8baf0c0127a9
	set res [poly1305_mac $msg $key]
	if {[cmp $res $std]} {
		puts std_$std
		puts res_$res
		return -code error "poly1305_mac error"
	}
}
