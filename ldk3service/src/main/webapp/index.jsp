<%@ page
   import="java.util.List,com.auth10.federation.Claim,com.auth10.federation.FederatedPrincipal,java.text.SimpleDateFormat,java.text.DateFormat,java.util.TimeZone,java.util.Date" 
   contentType="application/json; charset=UTF-8"
    pageEncoding="UTF-8"%>
{
   "Timestamp": 
   <% 
   TimeZone tz = TimeZone.getTimeZone("UTC");
   DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'"); 
   df.setTimeZone(tz);
   String nowAsISO = df.format(new Date());
   out.println("\"" + nowAsISO + "\",");
   %>
   "Claims":{
<%
   FederatedPrincipal principal = (FederatedPrincipal)request.getUserPrincipal(); 
   if (principal != null) {
      List<Claim> claims = principal.getClaims();
      boolean isFirst = true;
      for (Claim c : claims) {
         if (!isFirst)
         {
            out.println(",");
         }
         isFirst = false;
         out.print("\"" + c.getClaimType() + "\"");
         out.print(":");
         out.print("\"" + c.getClaimValue() + "\"");
      }
   }
%>
   }
}