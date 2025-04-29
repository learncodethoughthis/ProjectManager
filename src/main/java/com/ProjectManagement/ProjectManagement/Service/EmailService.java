package com.ProjectManagement.ProjectManagement.Service;
import com.ProjectManagement.ProjectManagement.Mailing.AbstractEmailContext;

public interface EmailService {

    void sendMail(AbstractEmailContext email) throws Exception;
}
