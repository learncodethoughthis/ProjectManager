package com.ProjectManagement.ProjectManagement.Mailing;

import com.ProjectManagement.ProjectManagement.Service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Service
public class DefaultEmailService implements EmailService  {
    private static final Logger logger = LoggerFactory.getLogger(DefaultEmailService.class);
    @Autowired
    private JavaMailSender emailSender;

    @Autowired
    private TemplateEngine templateEngine;

    public void sendMail(AbstractEmailContext email) throws MessagingException {
        logger.debug("Sending email to: {}, from: {}, subject: {}",
                email.getTo(), email.getFrom(), email.getSubject());
        MimeMessage message = emailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        Context context = new Context();
        context.setVariables(email.getContext());
        try {
            String html = templateEngine.process(email.getTemplateLocation(), context);
            helper.setTo(email.getTo());
            helper.setFrom(email.getFrom());
            helper.setSubject(email.getSubject());
            helper.setText(html, true);
            emailSender.send(message);
            logger.info("Email sent successfully to: {}", email.getTo());
        }catch (Exception e){
            logger.error("Failed to send email to: {}. Error: {}", email.getTo(), e.getMessage(), e);
            throw new MessagingException("Failed to send email", e);
        }
    }
}