package com.example.demo.controller;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;

import com.example.demo.services.kakaoService;

@Controller
public class loginController {

    @Autowired
    kakaoService ks;
    
    @GetMapping("login")
    public String loginPage()
    {
        return "index";
    }
    
    @ResponseBody
    @GetMapping("2")
    public String loginPage2()
    {
    	return "network con success";
    }

    @GetMapping("kakao")
    public String kakaoCallback(@RequestParam String code, Model model) throws IOException, ParseException {
        System.out.println("code = " + code);
        
        String host = "https://kauth.kakao.com/oauth/token";
        URL url = new URL(host);
        HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
        String token = "";
        try {
            urlConnection.setRequestMethod("POST");
            urlConnection.setDoOutput(true); // 데이터 기록 알려주기

            BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(urlConnection.getOutputStream()));
            StringBuilder sb = new StringBuilder();
            sb.append("grant_type=authorization_code");
            sb.append("&client_id=9f6654ba699444dc9bb1b25ccc505b0f");
            sb.append("&redirect_uri=http://localhost:8080/kakao");
            sb.append("&code=" + code);

            bw.write(sb.toString());
            bw.flush();

            int responseCode = urlConnection.getResponseCode();
            System.out.println("responseCode = " + responseCode);

            BufferedReader br = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String line = "";
            String result = "";
            while ((line = br.readLine()) != null) {
                result += line;
            }
            System.out.println("result = " + result);

            // json parsing
            JSONParser parser = new JSONParser();
            JSONObject elem = (JSONObject) parser.parse(result);

            String access_token = elem.get("access_token").toString();
            //String refresh_token = elem.get("refresh_token").toString();
            //System.out.println("refresh_token = " + refresh_token);
            //System.out.println("access_token = " + access_token);

            token = access_token;

            br.close();
            bw.close();
        } catch (IOException e) {
        	
            e.printStackTrace();
        } catch (ParseException e) {
        	
            e.printStackTrace();
        }
        
        //String access_token = ks.getToken(code); 
        Map<String, Object> userInfo = getUserInfo(token);
        model.addAttribute("code", code);
        model.addAttribute("access_token", token);
        model.addAttribute("userInfo", userInfo);
        
        return "/login/kakaoLoginInfo";
    }
    
    public Map<String, Object> getUserInfo(String access_token) throws IOException {
        String host = "https://kapi.kakao.com/v2/user/me";
        Map<String, Object> result = new HashMap<>();
        try {
            URL url = new URL(host);

            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setRequestProperty("Authorization", "Bearer " + access_token);
            urlConnection.setRequestMethod("GET");

            int responseCode = urlConnection.getResponseCode();
            System.out.println("responseCode = " + responseCode);


            BufferedReader br = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String line = "";
            String res = "";
            while((line=br.readLine())!=null)
            {
                res+=line;
            }

            System.out.println("res = " + res);

            JSONParser parser = new JSONParser();
            JSONObject obj = (JSONObject) parser.parse(res);
            JSONObject kakao_account = (JSONObject) obj.get("kakao_account");
            JSONObject properties = (JSONObject) obj.get("properties");

            String id = obj.get("id").toString();
            String nickname = properties.get("nickname").toString();
            String age_range = kakao_account.get("email").toString();

            result.put("id", id);
            result.put("nickname", nickname);
            result.put("email", age_range);

            br.close();


        } catch (IOException | ParseException e) {
            e.printStackTrace();
        }

        return result;
    }
    
    @GetMapping("naver")
    public String naverCallback(@RequestParam String code, @RequestParam String state, Model model) throws IOException, ParseException {
        System.out.println("code = " + code);
        System.out.println("code = " + state);

        // RestTemplate 인스턴스 생성
        RestTemplate rt = new RestTemplate();

        HttpHeaders accessTokenHeaders = new HttpHeaders();
        accessTokenHeaders.add("Content-type", "application/x-www-form-urlencoded");

        MultiValueMap<String, String> accessTokenParams = new LinkedMultiValueMap<>();
        accessTokenParams.add("grant_type", "authorization_code");
        accessTokenParams.add("client_id", "ht95rddVXfe5ulQjPVXI");
        accessTokenParams.add("client_secret", "QpD6V8mzfm");
        accessTokenParams.add("code" , code);	// 응답으로 받은 코드
        accessTokenParams.add("state" , state); // 응답으로 받은 상태

        HttpEntity<MultiValueMap<String, String>> accessTokenRequest = new HttpEntity<>(accessTokenParams, accessTokenHeaders);

        ResponseEntity<String> accessTokenResponse = rt.exchange(
                "https://nid.naver.com/oauth2.0/token",
                HttpMethod.POST,
                accessTokenRequest,
                String.class
        );

        System.out.println(accessTokenResponse.getBody());
        
        JSONParser parser = new JSONParser();
        JSONObject elem = (JSONObject) parser.parse(accessTokenResponse.getBody());
        
        String header = "Bearer " + elem.get("access_token").toString(); // Bearer 다음에 공백 추가
        String apiURL = "https://openapi.naver.com/v1/nid/me";

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put("Authorization", header);
        String responseBody = get(apiURL,requestHeaders);

        System.out.println("responseBody = " + responseBody);
        
        //String access_token = ks.getToken(code);
        model.addAttribute("code", requestHeaders.get("header"));
        model.addAttribute("access_token", state);
        model.addAttribute("userInfo", responseBody);
        
        return "/login/naverLoginInfo";
    }
    
	private static String get(String apiUrl, Map<String, String> requestHeaders){
	    HttpURLConnection con = connect(apiUrl);
	    try {
	        con.setRequestMethod("GET");
	        for(Map.Entry<String, String> header :requestHeaders.entrySet()) {
	            con.setRequestProperty(header.getKey(), header.getValue());
	        }
	
	
	        int responseCode = con.getResponseCode();
	        if (responseCode == HttpURLConnection.HTTP_OK) { // 정상 호출
	            return readBody(con.getInputStream());
	        } else { // 에러 발생
	            return readBody(con.getErrorStream());
	        }
	    } catch (IOException e) {
	        throw new RuntimeException("API 요청과 응답 실패", e);
	    } finally {
	        con.disconnect();
	    }
	}
	
	private static HttpURLConnection connect(String apiUrl){
	    try {
	        URL url = new URL(apiUrl);
	        return (HttpURLConnection)url.openConnection();
	    } catch (MalformedURLException e) {
	        throw new RuntimeException("API URL이 잘못되었습니다. : " + apiUrl, e);
	    } catch (IOException e) {
	        throw new RuntimeException("연결이 실패했습니다. : " + apiUrl, e);
	    }
	}
	
	private static String readBody(InputStream body){
	    InputStreamReader streamReader = new InputStreamReader(body);
	    
	    try (BufferedReader lineReader = new BufferedReader(streamReader)) {
	        StringBuilder responseBody = new StringBuilder();
	        
	        String line;
	        while ((line = lineReader.readLine()) != null) {
	            responseBody.append(line);
	        }
	        
	        return responseBody.toString();
	        
	    } catch (IOException e) {
	        throw new RuntimeException("API 응답을 읽는데 실패했습니다.", e);
	    }
	}

}