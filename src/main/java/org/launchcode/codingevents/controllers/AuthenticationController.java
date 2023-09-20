package org.launchcode.codingevents.controllers;

import org.launchcode.codingevents.data.UserRepository;
import org.launchcode.codingevents.models.User;
import org.launchcode.codingevents.models.dto.LoginFormDTO;
import org.launchcode.codingevents.models.dto.RegisterFormDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.Optional;

@Controller
public class AuthenticationController {

    @Autowired
    UserRepository userRepository;

    private static final String userSessionKey = "user";

    public User getUserFromSession(HttpSession session) {
        Integer userId = (Integer) session.getAttribute(userSessionKey);
        if (userId == null) {
            return null;
        }

        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            return null;
        }

        return user.get();
    }

    private static void setUserInSession(HttpSession session, User user) {
        session.setAttribute(userSessionKey, user.getId());
    }

    @GetMapping("/register")
    public String displayRegistrationForm(Model model) {
        model.addAttribute(new RegisterFormDTO());
        // pass RegisterFormDTO object in view as registerFormDTO since it does not have an attribute name
        model.addAttribute("title", "Register");
        return "register";
    }

    @PostMapping("/register")
    public String processRegistrationForm(@ModelAttribute @Valid RegisterFormDTO registerFormDTO, Errors errors,
                                          HttpServletRequest request, Model model) {

        //return user to the form if any validation errors occur
        // does this show the error messages from login form fields?
        if (errors.hasErrors()) {
            model.addAttribute("title", "Register");
            return "register";
        }

        // retrieving the user with the given username from the database
        User existingUser = userRepository.findByUsername(registerFormDTO.getUsername());


        // if existingUser does exist then it is rendered back to /register
        // and a custom error built with error object displays letting user know username already exists
        if (existingUser != null) {
            errors.rejectValue("username", "username.alreadyexists", "A user with that username already exists");
            model.addAttribute("title", "Register");
            return "register";
        }


        //defining password and verifyPassword to the password variable and verifyPassword variable
        // that was provided by user
        // using registerFormDTO to obtain them
        String password = registerFormDTO.getPassword();
        String verifyPassword = registerFormDTO.getVerifyPassword();


        //comparing the passwords to see if they match
        //  if they do not match then a custom error message will be displayed and
        // return the user to the form
        if (!password.equals(verifyPassword)) {
            errors.rejectValue("password", "passwords.mismatch", "Passwords do not match");
            model.addAttribute("title", "Register");
            return "register";
        }

        //at this point
        // a given username should not exist already  and all form data is valid
        // a new User object is created and it passes in the username and password they provided
        // it gets stored in the database and creates a new session for the user (session is created in the User class)
        // it is redirected to the home page
        User newUser = new User(registerFormDTO.getUsername(), registerFormDTO.getPassword());
        userRepository.save(newUser);
        setUserInSession(request.getSession(), newUser);

        return "redirect:";

    }

    // the login form
    // rendering the login form

    @GetMapping("/login")
    public String displayLoginForm(Model model) {
        model.addAttribute(new LoginFormDTO());
        model.addAttribute("title", "Log In");
        return "/login";
    }


    @PostMapping("/login")
    public String processLoginForm(@ModelAttribute @Valid LoginFormDTO loginFormDTO,
                                   Errors errors, HttpServletRequest request,
                                   Model model) {
        if (errors.hasErrors()) {
            model.addAttribute("title", "Log In");
            return "/login";
        }

        User theUser = userRepository.findByUsername(loginFormDTO.getUsername());

        if (theUser == null) {
            errors.rejectValue("username", "user.invalid", "The given username does not exist");
            model.addAttribute("title", "Log In");
            return "/login";
        }

        String password = loginFormDTO.getPassword();

        if (!theUser.isMatchingPassword(password)) {
            errors.rejectValue("password", "password.invalid", "Invalid password");
            model.addAttribute("title", "Log In");
            return "/login";
        }


        //creates a new session for the user
            setUserInSession(request.getSession(), theUser);

            return "redirect:";


    }

    // Logging out

    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        //removes all data rom the session
        // so when user makes a subsequent request
        // they will be forced to login again
        // commit to new branch accidently committed to user models branch ughhh
        request.getSession().invalidate();

        return "redirect:/login";
    }
}
