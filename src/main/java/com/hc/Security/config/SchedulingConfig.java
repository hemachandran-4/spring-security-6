package com.hc.Security.config;

import java.util.concurrent.Executor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

@Configuration
@EnableAsync
@EnableScheduling
public class SchedulingConfig implements SchedulingConfigurer{
    
    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
        taskScheduler.setPoolSize(10); // Set the number of threads
        taskScheduler.setThreadNamePrefix("scheduled-task-");
        taskScheduler.initialize();

        taskRegistrar.setTaskScheduler(taskScheduler);
    }

    @Bean(name = "asyncTaskExecutor")
    public Executor asyncTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);      // Minimum threads to keep alive
        executor.setMaxPoolSize(10);     // Maximum threads allowed
        executor.setQueueCapacity(25);   // How many tasks can wait in line
        executor.setThreadNamePrefix("async-worker-");
        executor.initialize();
        return executor;
    }
}
