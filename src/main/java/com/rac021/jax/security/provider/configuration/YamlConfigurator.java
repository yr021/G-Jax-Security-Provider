
package com.rac021.jax.security.provider.configuration ;

import java.io.File ;
import java.util.Map ;
import java.util.List ;
import javax.ejb.Startup ;
import java.util.HashMap ;
import java.io.FileReader ;
import java.util.ArrayList ;
import javax.inject.Singleton ;
import com.rac021.jax.api.crypto.AcceptType ;
import com.rac021.jax.api.crypto.CipherTypes ;
import com.esotericsoftware.yamlbeans.YamlReader ;
import com.rac021.jax.api.qualifiers.security.Policy ;
import com.rac021.jax.api.configuration.IConfigurator ;

/**
 *
 * @author ryahiaoui
 */

@Singleton
@Startup
public class YamlConfigurator implements IConfigurator      {

    private String pathConfig          = "serviceConf.yaml" ;
    private Map    configuration       = new HashMap()      ;
    private String authenticationType  = null               ;
    
    private String tableName           = "users"            ;
    private String loginColumnName     = "login"            ;
    private String passwordColumnName  = "password"         ;
    private String passwordStorage     = "MD5"              ;
    private String algoSign            = "SHA1"             ;
    
    private String loginSignature      = "PLAIN"            ;
    private String passwordSignature   = "MD5"              ;
    private String timeStampSignature  = "PLAIN"            ;
    private Long   validRequestTimeout = 30l                ;
    
    private String keycloakFile        = null               ;
    
    private int  RATIO                 =  1                 ;
    private int  ThreadPoolSize        =  4                 ;
    private int  responseCacheSize     =  500               ;
    private int  selectSize            =  5000              ;
    private int  maxConcurrentUsers    =  Integer.MAX_VALUE ;
    
    Map<String ,String >             security               ;
    
    Map<String ,List<CipherTypes> >  ciphers                ;
    Map<String ,List<AcceptType> >   acceptTypes            ;

    /* Server Configuration */
    
    private String  ip                = "localhost" ; 
    private String  httpPort          = "8080"      ;
    private String  httpsPort         = "8443"      ;
    private String  transport         = "HTTP"      ; // HTTPS 
    private boolean SelfSsl           = true        ; // false
 
    /* None SelfSSL Configuration */
    
    private String keyStorePassword   =  "admin"                        ;
    private String keyPassword        =  "admin"                        ;
    private String alias              =  "alias_name_admin"             ;
    private String keyStorePath       =  "/opt/my-release-key.keystore" ;

    
    /* File Config Properties */
    
    private final String TYPE                = "type"                ;
    private final String ALIAS               = "ALIAS"               ;
    private final String LOGIN               = "login"               ;
    private final String PLAIN               = "plain"               ;
    private final String _RATIO              = "Ratio"               ;
    private final String ACCEPT              = "Accept"              ;
    private final String CIPHERS             = "Ciphers"             ;
    private final String SECURED             = "secured"             ;
    private final String SELF_SSL            = "SELF_SSL"            ;
    private final String ALGOSIGN            = "algoSign"            ;
    private final String PASSWORD            = "password"            ;
    private final String TIMESTAMP           = "timeStamp"           ;
    private final String TABLENAME           = "tableName"           ;
    private final String TRANSPORT           = "TRANSPORT"           ;
    private final String HTTP_PORT           = "HTTP_PORT"           ;
    private final String HTTPS_PORT          = "HTTPS_PORT"          ;
    private final String CREDENTIALS         = "credentials"         ;
    private final String PARAMTOSIGN         = "paramToSign"         ;
    private final String SERVICECONF         = "serviceConf"         ;
    private final String KEYCLOAKFILE        = "keycloakFile"        ;
    private final String KEY_PASSWORD        = "KEY_PASSWORD"        ;
    private final String KEY_STORE_PATH      = "KEY_STORE_PATH"      ;
    private final String THREADPOOLSIZE      = "ThreadPoolSize"      ;
    private final String AUTHENTICATION      = "authentication"      ;
    private final String LOGINCOLUMNNAME     = "loginColumnName"     ;
    private final String RESPONSECACHESIZE   = "ResponseCacheSize"   ;
    private final String PASSWORDCOLUMNNAME  = "passwordColumnName"  ;
    private final String KEY_STORE_PASSWORD  = "KEY_STORE_PASSWORD"  ;
    private final String MAXCONCURRENTUSERS  = "MaxConcurrentUsers"  ;
    private final String VALIDREQUESTTIMEOUT = "validRequestTimeout" ;
    
    public YamlConfigurator() {

        security     = new HashMap<>() ;
        ciphers      = new HashMap<>() ;
        acceptTypes  = new HashMap<>() ;
        
        try {
            
             if(System.getProperty(SERVICECONF) != null)      {
                 pathConfig = System.getProperty(SERVICECONF) ;
             }
             
             if( pathConfig != null && new File(pathConfig).exists() )           {
                 YamlReader reader = new YamlReader( new FileReader(pathConfig)) ;
                 Object     object = reader.read() ;
                 Map        map    = (Map)object   ;            
                 configuration     = map           ;

                 setAuthenticationType()  ;
                 setCredentials()         ;
                 setAlgoSign()            ;
                 setParams()              ;
                 setSecurity()            ;
                 setRatio()               ;
                 setThreadPoolSize()      ;
                 setResponseCacheSize()   ;
                 setselectSize()          ;
                 setMaxConcurrentUsers()  ;
                 
                 setServerConfiguration() ;
                 setSelfConfiguration()   ;
 
             }
            
           } catch( Exception ex ) {
               ex.printStackTrace() ;       
           }
    }

   private void setAuthenticationType() {
       
      if( ((Map)this.configuration.get(AUTHENTICATION)) == null )  {
          authenticationType = Policy.Public.name().toLowerCase() ;
      }
      else {
          
         authenticationType = (String) ((Map)this.configuration.get(AUTHENTICATION)).get( TYPE )
                                                 .toString().replaceAll(" +", " ").trim()          ; 
         
         if( authenticationType.equalsIgnoreCase(Policy.SSO.name()))
             keycloakFile  =  (String) ((Map)this.configuration
                                                 .get(AUTHENTICATION)).get( KEYCLOAKFILE )
                                                 .toString().replaceAll(" +", " ").trim()    ; 
      }
   }
        
   private void setAlgoSign() {
        
        if( this.configuration.get(AUTHENTICATION) != null ) {
             
           if( ( ( (String) ((Map)this.configuration.get(AUTHENTICATION)).get(TYPE))
                                                    .equalsIgnoreCase(Policy.CustomSignOn.name()))) {
               
              this.algoSign = (String) ((Map)this.configuration.get(AUTHENTICATION))
                                                 .get(ALGOSIGN)
                                                 .toString().replaceAll(" +", " ").trim() ;         
           }
        }
    }

    public String getAlgoSign() {
        return algoSign ;
    }
    
    private void setParams() {
        
        if( this.configuration.get(AUTHENTICATION) != null ) {
            
            if( ( ( (String) ((Map)this.configuration.get(AUTHENTICATION)).get(TYPE))
                                                     .equalsIgnoreCase(Policy.CustomSignOn.name())) ) {
                
               this.loginSignature      = (String) ( (Map) ((Map)this.configuration
                                                                     .get(AUTHENTICATION))
                                                                     .get(PARAMTOSIGN))
                                                                     .get(LOGIN).toString()
                                                                     .replaceAll(" +", " ").trim() ;
               
               this.passwordSignature   = (String) ( (Map) ((Map)this.configuration
                                                                     .get(AUTHENTICATION))
                                                                     .get(PARAMTOSIGN))
                                                                     .get(PASSWORD).toString()
                                                                     .replaceAll(" +", " ").trim() ;
               
               this.timeStampSignature  = (String) ( (Map) ((Map)this.configuration
                                                                     .get(AUTHENTICATION))
                                                                     .get(PARAMTOSIGN))
                                                                     .get(TIMESTAMP).toString()
                                                                     .replaceAll(" +", " ").trim() ;
               
               this.validRequestTimeout = Long.parseLong( ( (String) ((Map)this.configuration
                                                                               .get(AUTHENTICATION))
                                                                               .get(VALIDREQUESTTIMEOUT)) ) ;
            }
        }
    }

    private void setSecurity() {
        
        if( getAuthenticationType() == null ) {
            authenticationType = Policy.Public.name().toLowerCase() ;
            return ;
        }
        
        if( getAuthenticationType().equalsIgnoreCase(Policy.SSO.name())) {
           if( getAuthenticationInfos() != null ) {
              ((Map)getAuthenticationInfos().get(SECURED)).keySet().forEach( _sName -> {
                   security.put((String) _sName, Policy.SSO.name() ) ;
              }) ;
           }
        }
        
        else if( getAuthenticationType().equalsIgnoreCase(Policy.CustomSignOn.name())) {
            
           if( getAuthenticationInfos() != null ) {
               
                ( (Map<String, Map>) ((Map) this.configuration.get(AUTHENTICATION)).get(SECURED))
                                           
                        .forEach((k, v) -> {
                           
                                    String _sName = k ;
                                    security.put(_sName, Policy.CustomSignOn.name() ) ;

                                    Map<String, Object > serviceSescription = v ;

                                    serviceSescription.forEach((n, m ) -> { 
                                        
                                         if( n.equals(ACCEPT)) {
                                             List<String> mm = ((List<String>) m) ;
                                            ( mm ).replaceAll(String::toUpperCase ) ;
                                             this.acceptTypes.put(_sName, AcceptType.toList( mm) ) ;
                                         }
                                         
                                         if( n.equals(CIPHERS)) {
                                             List<String> mm = ((List<String>) m) ;
                                             mm.replaceAll ( String::toUpperCase ) ;
                                             List<CipherTypes> typed = CipherTypes.toList( mm )    ;
                                             this.ciphers.put(_sName, typed ) ;
                                         }
                                        
                                    }) ;
                        }) ; 
           }
        }
    }
    
    private void setCredentials() {
        
        if( this.configuration.get(AUTHENTICATION) != null ) {
            
            if( ( ( (String) ((Map) this.configuration.get(AUTHENTICATION)).get(TYPE))
                                                      .equalsIgnoreCase(Policy.CustomSignOn.name())) ) {
                
                this.tableName          = ( String) ( (Map) ((Map)this.configuration
                                                                      .get(AUTHENTICATION))
                                                                      .get(CREDENTIALS))
                                                                      .get(TABLENAME).toString()
                                                                      .replaceAll(" +", " ").trim() ;
                
                this.loginColumnName    = ( String) ( (Map) ((Map)this.configuration
                                                                      .get(AUTHENTICATION))
                                                                      .get(CREDENTIALS))
                                                                      .get(LOGINCOLUMNNAME).toString()
                                                                      .replaceAll(" +", " ").trim() ;
                
                this.passwordColumnName = ((String) ( (Map) ((Map)this.configuration
                                                                      .get(AUTHENTICATION))
                                                                      .get(CREDENTIALS))
                                                                      .get(PASSWORDCOLUMNNAME))
                                                                      .replaceAll(" +", " ")
                                                                      .split(" -> ")[0].trim() ; 

                this.passwordStorage = ((String) ( (Map) ((Map)this.configuration
                                                                   .get(AUTHENTICATION))
                                                                   .get(CREDENTIALS))
                                                                   .get(PASSWORDCOLUMNNAME))
                                                                   .contains(" -> ") ?
                                       ((String) ( (Map) ((Map)this.configuration
                                                                   .get(AUTHENTICATION))
                                                                   .get(CREDENTIALS))
                                                                   .get(PASSWORDCOLUMNNAME))
                                                                   .replaceAll(" +", " ").trim()
                                                                   .split(" -> ")[1]    :
                                       PLAIN ;
            }
        }
    }
    
    public  Map getConfiguration() {
        return configuration;
    }
    
    private void setRatio() {
       if(( getConfiguration().get(_RATIO)) != null )   {
           this.RATIO = Integer.parseInt((String) getConfiguration().get(_RATIO)) ;
       }
    }

    private void setThreadPoolSize() {
       if(( getConfiguration().get(THREADPOOLSIZE)) != null )  {
         this.ThreadPoolSize = Integer.parseInt((String) getConfiguration()
                                      .get(THREADPOOLSIZE)) ;
       }
    }

    private void setResponseCacheSize() {
       if((getConfiguration().get(RESPONSECACHESIZE)) != null )  {
         this.responseCacheSize = Integer.parseInt((String) getConfiguration()
                                         .get(RESPONSECACHESIZE))  ;
       }
    }
    private void setMaxConcurrentUsers() {
       if((getConfiguration().get(MAXCONCURRENTUSERS)) != null )  {
         this.maxConcurrentUsers= Integer.parseInt((String) getConfiguration()
                                         .get(MAXCONCURRENTUSERS)) ;
       }
    }

    private void setselectSize() {
      if((getConfiguration().get("SelectSize")) != null )  {
        this.selectSize     = Integer.parseInt((String) getConfiguration()
                                     .get("SelectSize")) ;
      }
    }
    
    private void setServerConfiguration() {
 
       if((getConfiguration().get("IP")) != null )                {
         this.ip = (String) getConfiguration()
                             .get("IP") ;
       }
       if((getConfiguration().get(HTTP_PORT)) != null )           {
         this.httpPort = (String) getConfiguration()
                             .get(HTTP_PORT) ;
       }
       if((getConfiguration().get(HTTPS_PORT)) != null )          {
         this.httpsPort = (String) getConfiguration()
                             .get(HTTPS_PORT) ;
       }
       if((getConfiguration().get(TRANSPORT)) != null )           {
         this.transport = (String) getConfiguration()
                             .get(TRANSPORT) ;
       }
       if((getConfiguration().get(SELF_SSL)) != null )            {
         this.SelfSsl = Boolean.valueOf ( (String) 
                               getConfiguration().get(SELF_SSL) ) ;
       }
    }

    private void setSelfConfiguration() {
   
      if((getConfiguration().get(KEY_STORE_PATH)) != null )      {
         this.keyStorePath = (String) getConfiguration()
                             .get(KEY_STORE_PATH) ;
       }
       if((getConfiguration().get(KEY_STORE_PASSWORD)) != null ) {
         this.keyStorePassword = (String) getConfiguration()
                             .get(KEY_STORE_PASSWORD) ;
       }
       if((getConfiguration().get(KEY_PASSWORD)) != null )       {
         this.keyPassword = (String) getConfiguration()
                             .get(KEY_PASSWORD) ;
       }
       if((getConfiguration().get(ALIAS)) != null )              {
         this.alias = (String) getConfiguration()
                             .get(ALIAS) ;
       }
    }
  
    @Override
    public Long getValidRequestTimeout() {
        return validRequestTimeout;
    }

    public List<CipherTypes> getCiphers(String serviceCode)              { 
      return ciphers.getOrDefault( serviceCode, new ArrayList<>() )      ;
    }
    
    public List<AcceptType> getAcceptTypes(String serviceCode)          { 
      return acceptTypes.getOrDefault( serviceCode, new ArrayList<>() ) ;
    }
    
    public String getAuthenticationType() {      
       return authenticationType ;
    }
   
    public Map getAuthenticationInfos() {
       return (Map)((Map) this.configuration.get(AUTHENTICATION)) ;
    }

    public String getAuthenticationType(String serviceCode) {
      return security.getOrDefault( serviceCode, 
                                    Policy.Public.name().toLowerCase() ) ;
    }

    public String getPathConfig() {
        return pathConfig ;
    }

    public String getTableName() {
        return tableName ;
    }

    public String getLoginColumnName()    {
        return loginColumnName ;
    }

    public String getPasswordColumnName() {
        return passwordColumnName ;
    }

    public String getLoginSignature()     {
        return loginSignature ;
    }

    public String getPasswordSignature()  {
        return passwordSignature;
    }

    public String getTimeStampSignature() {
        return timeStampSignature ;
    }

    public Map<String, String> getSecurity() {
        return security ;
    }

    public void setKeycloakFile(String keycloakFile ) {
        this.keycloakFile = keycloakFile ;
    }

    public String getKeycloakFile()    {
        return keycloakFile ;
    }
          
    public String getPasswordStorage() {
        return passwordStorage ;
    }
   
    
    public int getRatio()              {
       return RATIO ;
    }

    public int getThreadPoolSize()     {
       return ThreadPoolSize ;
    }

    public int getResponseCacheSize()  {
       return responseCacheSize ;
    }

    public int getSelectSize() {
       return selectSize       ;
    }

    public int getMaxConcurrentUsers() {
        return maxConcurrentUsers ;
    }

    public String getIp()        {
        return ip ;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getHttpPort() {
        return httpPort ;
    }

    public void setHttpPort(String httpPort) {
        this.httpPort = httpPort ;
    }

    public String getHttpsPort() {
        return httpsPort ;
    }

    public void setHttpsPort(String httpsPort) {
        this.httpsPort = httpsPort ;
    }

    public String getTransport() {
        return transport ;
    }

    public void setTransport(String transport) {
        this.transport = transport ;
    }

    public boolean getSelfSsl()                {
        return SelfSsl ;
    }

    public void setSelfSsl( boolean SelfSsl)   {
        this.SelfSsl = SelfSsl ;
    }

    public String getKeytorePassword()         {
        return keyStorePassword ;
    }

    public void setKeytorePassword(String keytorePassword) {
        this.keyStorePassword = keytorePassword ;
    }

    public String getKeyPassword() {
        return keyPassword ;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword ;
    }

    public String getAlias()           {
        return alias ;
    }

    public void setAlias(String alias) {
        this.alias = alias ;
    }

    public String getKeyStorePath()    {
        return keyStorePath ;
    }

    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath ;
    }

}
