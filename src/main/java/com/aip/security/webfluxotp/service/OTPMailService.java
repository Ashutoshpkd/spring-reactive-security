package com.aip.security.webfluxotp.service;

import com.aip.security.webfluxotp.configuration.EmailProperties;
import com.aip.security.webfluxotp.domain.document.User;
import com.aip.security.webfluxotp.service.mapper.dto.EmailSenderDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring5.SpringTemplateEngine;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Service for sending emails.
 */
@Service
public class OTPMailService implements SendOTP {
    private static final Logger LOGGER = LoggerFactory.getLogger(OTPMailService.class);
    private static final String USER = "user";
    private static final String BASE_URL = "baseUrl";
    private static final String DEFAULT_LANGUAGE = "en";
    private final EmailProperties emailProperties;
    private final JavaMailSender javaMailSender;
    private final MessageSource messageSource;
    private final SpringTemplateEngine templateEngine;

    public OTPMailService(
            EmailProperties emailProperties,
        JavaMailSender javaMailSender,
        MessageSource messageSource,
        SpringTemplateEngine templateEngine
    ) {
        this.emailProperties = emailProperties;
        this.javaMailSender = javaMailSender;
        this.messageSource = messageSource;
        this.templateEngine = templateEngine;
    }

    private void sendEmail(EmailSenderDTO sender) {

        // Prepare message using a Spring helper
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        try {
            LOGGER.info("Email is being sent by: {}", emailProperties);
            MimeMessageHelper message = new MimeMessageHelper(mimeMessage, sender.isMultipart(), StandardCharsets.UTF_8.name());
            message.setTo(sender.getTo());
            message.setFrom(emailProperties.getFrom());
            message.setSubject(sender.getSubject());
            message.setText(sender.getContent(), sender.isHtml());
            javaMailSender.send(mimeMessage);
            LOGGER.info("Sent email to User '{}'", sender.getTo());
        } catch (MailException | MessagingException e) {
            LOGGER.warn("Email could not be sent to user '{}'", sender.getTo(), e);
        }
    }

    private void sendEmailFromTemplate(User user, String templateName, String titleKey) {
        if (user.getEmail() == null) {
            LOGGER.debug("Email doesn't exist for user '{}'", user.getEmail());
            return;
        }
        Locale locale = Locale.forLanguageTag(DEFAULT_LANGUAGE);
        Context context = new Context(locale);
        context.setVariable(USER, user);
        context.setVariable(BASE_URL, emailProperties.getBaseUrl());
        String content = templateEngine.process(templateName, context);
        String subject = messageSource.getMessage(titleKey, null, locale);

        LOGGER.info("Sending email to: {}, {}, {}", subject, user.getEmail());
        sendEmail(EmailSenderDTO.builder()
                .content(content).subject(subject).to(user.getEmail())
                .isHtml(true).isMultipart(false)
                .build());
    }

    @Async
    @Override
    public void sendOTP(User user) {
        LOGGER.info("Sending login OTP email to '{}'", user);
        sendEmailFromTemplate(user, "mail/OTPCodeEmail", "email.otp.verification");
    }
}
