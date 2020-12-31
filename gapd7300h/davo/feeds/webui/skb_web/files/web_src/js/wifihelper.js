var band = {
	"band24":[
		{"mode":"11b"},
		{"mode":"11g"},
		{"mode":"11bg"},
		{"mode":"11n"},
		{"mode":"11ng"},
		{"mode":"11bgn"}
	],
	"band5":[
		{"mode":"11a"},
		{"mode":"11n"},
		{"mode":"11na"},
		{"mode":"11nac"},
		{"mode":"11ac_only"},
		{"mode":"11ac"}
	]
};
var band_val = {
	"band24":[
		{"mode":"B"},
		{"mode":"G"},
		{"mode":"B+G"},
		{"mode":"N"},
		{"mode":"G+N"},
		{"mode":"B+G+N"}
	],
	"band5":[
		{"mode":"A"},
		{"mode":"N"},
		{"mode":"A+N"},
		{"mode":"N+AC"},
		{"mode":"AC"},
		{"mode":"A+N+AC"}
	]
};
var band_width = {
	"band24":[
		{"mode":"dv_auto"},
		{"mode":"HT20"},
		{"mode":"HT40"}
	],
	"band5":[
		{"mode":"HT20"},
		{"mode":"HT40"},
		{"mode":"HT80"},
		{"mode":"HT80_80"},
		{"mode":"HT160"}
	]
};
var band_width_val = {
	"band24":[
		{"mode":"자동"},
		{"mode":"20MHz"},
		{"mode":"20/40MHz"}
	],
	"band5":[
		{"mode":"20MHz"},
		{"mode":"20/40MHz"},
		{"mode":"20/40/80MHz"},
		{"mode":"20/40/80/80+80MHz"},
		{"mode":"20/40/80/160MHz"}
	]
};
var ch = {
	"band24":[
		{"ch":"auto","arrow":"all"},
		{"ch":"1","arrow":"low"},
		{"ch":"2","arrow":"low"},
		{"ch":"3","arrow":"low"},
		{"ch":"4","arrow":"low"},
		{"ch":"5","arrow":"mid"},
		{"ch":"6","arrow":"mid"},
		{"ch":"7","arrow":"mid"},
		{"ch":"8","arrow":"mid"},
		{"ch":"9","arrow":"mid"},
		{"ch":"10","arrow":"high"},
		{"ch":"11","arrow":"high"},
		{"ch":"12","arrow":"high"},
		{"ch":"13","arrow":"high"}
	],
	"band5":[
		{"ch":"auto","dfs":false, "ht80": true, "ht160":true},
		{"ch":"36","dfs":false, "ht80": true, "ht160":true},
		{"ch":"40","dfs":false, "ht80": true, "ht160":true},
		{"ch":"44","dfs":false, "ht80": true, "ht160":true},
		{"ch":"48","dfs":false, "ht80": true, "ht160":true},
		{"ch":"52","dfs":true, "ht80": true, "ht160":true},
		{"ch":"56","dfs":true, "ht80": true, "ht160":true},
		{"ch":"60","dfs":true, "ht80": true, "ht160":true},
		{"ch":"64","dfs":true, "ht80": true, "ht160":true},
		{"ch":"100","dfs":true, "ht80": true, "ht160":false},
		{"ch":"104","dfs":true, "ht80": true, "ht160":false},
		{"ch":"108","dfs":true, "ht80": true, "ht160":false},
		{"ch":"112","dfs":true, "ht80": true, "ht160":false},
		{"ch":"116","dfs":true, "ht80": false, "ht160":false},
		{"ch":"120","dfs":true, "ht80": false, "ht160":false},
		{"ch":"124","dfs":false, "ht80": false, "ht160":false},
		{"ch":"149","dfs":false, "ht80": true, "ht160":false},
		{"ch":"153","dfs":false, "ht80": true, "ht160":false},
		{"ch":"157","dfs":false, "ht80": true, "ht160":false},
		{"ch":"161","dfs":false, "ht80": true, "ht160":false}
	]
};
var ch_val = {
	"band24":[
		{"ch":"Auto","arrow":"all"},
		{"ch":"1","arrow":"low"},
		{"ch":"2","arrow":"low"},
		{"ch":"3","arrow":"low"},
		{"ch":"4","arrow":"low"},
		{"ch":"5","arrow":"mid"},
		{"ch":"6","arrow":"mid"},
		{"ch":"7","arrow":"mid"},
		{"ch":"8","arrow":"mid"},
		{"ch":"9","arrow":"mid"},
		{"ch":"10","arrow":"high"},
		{"ch":"11","arrow":"high"},
		{"ch":"12","arrow":"high"},
		{"ch":"13","arrow":"high"}
	],
	"band5":[
		{"ch":"Auto","dfs":false, "ht80": true, "ht160":true},
		{"ch":"36","dfs":false, "ht80": true, "ht160":true},
		{"ch":"40","dfs":false, "ht80": true, "ht160":true},
		{"ch":"44","dfs":false, "ht80": true, "ht160":true},
		{"ch":"48","dfs":false, "ht80": true, "ht160":true},
		{"ch":"52","dfs":true, "ht80": true, "ht160":true},
		{"ch":"56","dfs":true, "ht80": true, "ht160":true},
		{"ch":"60","dfs":true, "ht80": true, "ht160":true},
		{"ch":"64","dfs":true, "ht80": true, "ht160":true},
		{"ch":"100","dfs":true, "ht80": true, "ht160":false},
		{"ch":"104","dfs":true, "ht80": true, "ht160":false},
		{"ch":"108","dfs":true, "ht80": true, "ht160":false},
		{"ch":"112","dfs":true, "ht80": true, "ht160":false},
		{"ch":"116","dfs":true, "ht80": false, "ht160":false},
		{"ch":"120","dfs":true, "ht80": false, "ht160":false},
		{"ch":"124","dfs":false, "ht80": false, "ht160":false},
		{"ch":"149","dfs":false, "ht80": true, "ht160":false},
		{"ch":"153","dfs":false, "ht80": true, "ht160":false},
		{"ch":"157","dfs":false, "ht80": true, "ht160":false},
		{"ch":"161","dfs":false, "ht80": true, "ht160":false}
	]
};