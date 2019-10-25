package dev.ponicode;

import java.util.Date;
import java.util.StringTokenizer;

public class User {
    private String firstname;
    private String lastname;
    private Date customerSince;

    public User(String firstname, String lastname) {
        this.firstname = firstname;
        this.lastname = lastname;
        this.customerSince = new Date();
    }

    public boolean alreadyCustomer(Date date) {
        return date.compareTo(customerSince) >= 0;
    }

    public long timeCustomer(Date currDate) {
        if (currDate != null)
            return currDate.getTime() - customerSince.getTime();
        return -1L;
    }

    public void setName(StringTokenizer strtok) {
        if (!strtok.hasMoreTokens())
            return;
        if (strtok.hasMoreTokens())
            firstname = strtok.nextToken();
        if (strtok.hasMoreTokens())
            lastname = strtok.nextToken();
    }

    public boolean customerDuringPromotion(Date start, Date end) throws IllegalArgumentException {
        if (start == null)
            throw new IllegalArgumentException();
        if (start.compareTo(customerSince) >= 0 && end.compareTo(customerSince) <= 0)
            return true;
        return false;
    }

    //public boolean hasSameLastname(User user)
}
