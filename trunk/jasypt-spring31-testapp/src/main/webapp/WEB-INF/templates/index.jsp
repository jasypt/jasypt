<%@ taglib prefix="sf" uri="http://www.springframework.org/tags/form" %><%@ 
taglib prefix="s" uri="http://www.springframework.org/tags" %><%@
taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %><%@ 
page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%><!DOCTYPE html>

<html>

  <head>
    <title>Jasypt Spring3 Test Application</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <link rel="stylesheet" type="text/css" media="all" href="<s:url value='/css/thvsjsp.css' />"/>
  </head>

  <body>

    <h2>This is a JSP</h2>

    <div>    
      <c:out value="${encMba}" />
    </div>
    <div>    
      <c:out value="${encMs}" />
    </div>

  </body>
  
</html>