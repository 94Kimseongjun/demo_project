
package co.kr.ntels.demo_project.aop;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;

@Component
@Aspect
@Slf4j
public class LoggingAspect {

    @Pointcut("execution(public * co.kr.ntels..*Controller.*(..))")
    public void onRequest() {}

    @Around("onRequest()")
    public Object doLogging(ProceedingJoinPoint pjp) throws Throwable{
        String methodName = pjp.getSignature().getName();
        String className = pjp.getTarget().getClass().getName();
        log.info("Method {} in class {} is invoked.", methodName, className);

        Object result = pjp.proceed();

        log.info("Method {} in class {} has finished executing with result {}.", methodName, className, result);
        return result;
    }

}

