<!DOCTYPE html>
<html lang="UTF-8">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="content-type" content="text/html; charset=utf-8">
<title>agent 列表</title>
</head>
<body>
  <h2>Agent列表</h2>
  <div>
     <ul>
        <#list users as user>
         <li>
             <span>${user.id}</span>-
             <span>${user.name}</span>-
             <span>${user.age}</span>-
             <span>${user.address}</span>
         </li>
         </#list>
     </ul>
   </div>
</body>
</html>
