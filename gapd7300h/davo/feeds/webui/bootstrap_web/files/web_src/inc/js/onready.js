var cur_file_name = $("#ui_file").val();
var cur_folder_name = $("#ui_folder").val();
if(cur_file_name != ""){
	console.log(cur_file_name);
	$("."+cur_file_name).addClass("active");
	var i = 0;
	var lobj = $("."+cur_file_name).parent("ul");
	if($("#side-menu").length != 0){
		if(lobj.attr("id") != "side-menu"){
			lobj = lobj.parent("li");
		}else{
			i=1;
		}
		while(i == 0)
		{
			if(lobj.parent("ul").attr("id") != undefined && lobj.parent("ul").attr("id") == "side-menu"){
				i = 1;
				lobj.addClass("active");
			}else{
				lobj.addClass("active");
				lobj = lobj.parent("ul").parent("li");
				console.log("not found",i);
			}
		}
	}
}else{
	$(".index").addClass("active");
}
if(cur_folder_name != ""){
	$("."+cur_folder_name).addClass("active");
}