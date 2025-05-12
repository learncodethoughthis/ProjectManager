package com.ProjectManagement.ProjectManagement.Mailing;

public interface EmailService {

    void sendMail(AbstractEmailContext email) throws Exception;
}
