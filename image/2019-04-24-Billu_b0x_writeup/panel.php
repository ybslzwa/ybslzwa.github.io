<?php
session_start();

include('c.php');
include('head2.php');
if(@$_SESSION['logged']!=true )
{
		header('Location: index.php', true, 302);
		exit();
	
}



echo "Welcome to billu b0x ";
echo '<form method=post style="margin: 10px 0px 10px 95%;"><input type=submit name=lg value=Logout></form>';
if(isset($_POST['lg']))
{
	unset($_SESSION['logged']);
	unset($_SESSION['admin']);
	header('Location: index.php', true, 302);
}
echo '<hr><br>';

echo '<form method=post>

<select name=load>
    <option value="show">Show Users</option>
	<option value="add">Add User</option>
</select> 

 &nbsp<input type=submit name=continue value="continue"></form><br><br>';
if(isset($_POST['continue']))
{
	$dir=getcwd();
	$choice=str_replace('./','',$_POST['load']);
	
	if($choice==='add')
	{
       		include($dir.'/'.$choice.'.php');
			die();
	}
	
        if($choice==='show')
	{
        
		include($dir.'/'.$choice.'.php');
		die();
	}
	else
	{
		include($dir.'/'.$_POST['load']);
	}
	
}


if(isset($_POST['upload']))
{
	
	$name=mysqli_real_escape_string($conn,$_POST['name']);
	$address=mysqli_real_escape_string($conn,$_POST['address']);
	$id=mysqli_real_escape_string($conn,$_POST['id']);
	
	if(!empty($_FILES['image']['name']))
	{
		$iname=mysqli_real_escape_string($conn,$_FILES['image']['name']);
	$r=pathinfo($_FILES['image']['name'],PATHINFO_EXTENSION);
	$image=array('jpeg','jpg','gif','png');
	if(in_array($r,$image))
	{
		$finfo = @new finfo(FILEINFO_MIME); 
	$filetype = @$finfo->file($_FILES['image']['tmp_name']);
		if(preg_match('/image\/jpeg/',$filetype )  || preg_match('/image\/png/',$filetype ) || preg_match('/image\/gif/',$filetype ))
				{
					if (move_uploaded_file($_FILES['image']['tmp_name'], 'uploaded_images/'.$_FILES['image']['name']))
							 {
							  echo "Uploaded successfully ";
							  $update='insert into users(name,address,image,id) values(\''.$name.'\',\''.$address.'\',\''.$iname.'\', \''.$id.'\')'; 
							 mysqli_query($conn, $update);
							  
							}
				}
			else
			{
				echo "<br>i told you dear, only png,jpg and gif file are allowed";
			}
	}
	else
	{
		echo "<br>only png,jpg and gif file are allowed";
		
	}
}


}

?>
