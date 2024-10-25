package spring.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    @GetMapping("/home")
    public  String getHome (Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            model.addAttribute("email", authentication.getName());
            model.addAttribute("role", authentication.getAuthorities().toString());
        }
        model.addAttribute("value", "Welcome to home page.");
        return "home.html";
    }
}
