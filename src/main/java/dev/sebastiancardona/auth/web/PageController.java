package dev.sebastiancardona.auth.web;

import dev.sebastiancardona.auth.invite.InviteService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Validated
public class PageController {

    private final InviteService inviteService;

    public PageController(InviteService inviteService) {
        this.inviteService = inviteService;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/")
    public String home() {
        // no app lives here; the only sensible landing is the account page… which is v2.
        return "redirect:/login";
    }

    @GetMapping("/register")
    public String register(@RequestParam(name = "invite", required = false) String invite, Model model) {
        boolean valid = invite != null && inviteService.peek(invite).isPresent();
        model.addAttribute("invite", invite);
        model.addAttribute("inviteValid", valid);
        return "register";
    }

    @PostMapping("/register")
    public String doRegister(
            @RequestParam("invite") @NotBlank String invite,
            @RequestParam("email") @Email @NotBlank String email,
            @RequestParam("password") @Size(min = 10, max = 200) String password,
            @RequestParam("displayName") @NotBlank @Size(max = 100) String displayName,
            HttpServletRequest request,
            Model model) {
        try {
            inviteService.redeem(invite, email, password, displayName, clientIp(request));
        } catch (InviteService.InvalidInviteException e) {
            model.addAttribute("invite", invite);
            model.addAttribute("inviteValid", true); // let them retry (e.g. duplicate email)
            model.addAttribute("error", e.getMessage());
            return "register";
        }
        return "redirect:/login?registered";
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded != null ? forwarded.split(",")[0].trim() : request.getRemoteAddr();
    }
}
