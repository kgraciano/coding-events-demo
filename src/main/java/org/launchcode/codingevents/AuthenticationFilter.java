package org.launchcode.codingevents;

import org.launchcode.codingevents.controllers.AuthenticationController;
import org.launchcode.codingevents.data.UserRepository;
import org.launchcode.codingevents.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class AuthenticationFilter extends HandlerInterceptorAdapter {

    @Autowired
    UserRepository userRepository;

    @Autowired
    AuthenticationController authenticationController;

    private static final List<String> whitelist = Arrays.asList("/login", "/register", "/logout", "/css");



    // takes in a String representing the URL path
    // checks to see if it starts with any of the entries in whitelist
    // loops through each element in the array list and compares the path youre in
    // to the paths in whitelist
    // if they match then they are accessible without logging in
    private static boolean isWhitelisted(String path) {
        for (String pathRoot : whitelist) {
            if (path.startsWith(pathRoot)) {
                return true;
            }
        }

        //if not then method returns false
        return false;
    }


    //this method prevents access to every page on the app if a user is not logged in yet
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {


        //dont require sign-in for whitelisted pages
        //request.getRequestURI() returns the request path.
        if (isWhitelisted(request.getRequestURI())) {

            //returning true indicates that the request may proceed
            return true;
        }


        HttpSession session = request.getSession();
        User user = authenticationController.getUserFromSession(session);

        //the user is logged in
        // request process will continue
        if (user != null) {
            return true;
        }

        //the user is not logged in
        // no controller will be called and be redirected to login page to log in
        response.sendRedirect("/login");
        return false;
    }


}
