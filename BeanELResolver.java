/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package javax.el;

import java.beans.BeanInfo;
import java.beans.FeatureDescriptor;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

public class BeanELResolver extends ELResolver {

    private static final int CACHE_SIZE;
    private static final String CACHE_SIZE_PROP =
        "org.apache.el.BeanELResolver.CACHE_SIZE";

    static {
        String cacheSizeStr;
        if (System.getSecurityManager() == null) {
            cacheSizeStr = System.getProperty(CACHE_SIZE_PROP, "1000");
        } else {
            cacheSizeStr = AccessController.doPrivileged(
                    new PrivilegedAction<String>() {

                    @Override
                    public String run() {
                        return System.getProperty(CACHE_SIZE_PROP, "1000");
                    }
                });
        }
        CACHE_SIZE = Integer.parseInt(cacheSizeStr);
    }

    private final boolean readOnly;

    private final ConcurrentCache<String, BeanProperties> cache =
        new ConcurrentCache<>(CACHE_SIZE);

    public BeanELResolver() {
        this.readOnly = false;
    }

    public BeanELResolver(boolean readOnly) {
        this.readOnly = readOnly;
    }

    @Override
    public Class<?> getType(ELContext context, Object base, Object property) {
        Objects.requireNonNull(context);
        if (base == null) {
            return null;
        }
	if (property == null) {
	    return null;
	}

        context.setPropertyResolved(base, property);
        return this.property(context, base, property).getPropertyType();
    }

    @Override
    public Object getValue(ELContext context, Object base, Object property) {
        Objects.requireNonNull(context);
        if (base == null || property == null) {
            return null;
        }

        context.setPropertyResolved(base, property);
        Method m = this.property(context, base, property).read(context, base);
        try {
            return m.invoke(base, (Object[]) null);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            Util.handleThrowable(cause);
            throw new ELException(Util.message(context, "propertyReadError",
                    base.getClass().getName(), property.toString()), cause);
        } catch (Exception e) {
            throw new ELException(e);
        }
    }

    @Override
    public void setValue(ELContext context, Object base, Object property,
            Object value) {
        Objects.requireNonNull(context);
        if (base == null || property == null) {
            return;
        }

        context.setPropertyResolved(base, property);

        if (this.readOnly) {
            throw new PropertyNotWritableException(Util.message(context,
                    "resolverNotWriteable", base.getClass().getName()));
        }

        Method m = this.property(context, base, property).write(context, base);
        try {
            m.invoke(base, value);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            Util.handleThrowable(cause);
            throw new ELException(Util.message(context, "propertyWriteError",
                    base.getClass().getName(), property.toString()), cause);
        } catch (Exception e) {
            throw new ELException(e);
        }
    }

    /**
     * @since EL 2.2
     */
    @Override
    public Object invoke(ELContext context, Object base, Object method,
            Class<?>[] paramTypes, Object[] params) {
        Objects.requireNonNull(context);
        ExpressionFactory factory = ELManager.getExpressionFactory();

        String methodName = (String) factory.coerceToType(method, String.class);

        // Find the matching method
        Method matchingMethod =
                Util.findMethod(base.getClass(), base, methodName, paramTypes, params);

        Object[] parameters = Util.buildParameters(
                matchingMethod.getParameterTypes(), matchingMethod.isVarArgs(),
                params);

        Object result = null;
        try {
            result = matchingMethod.invoke(base, parameters);
        } catch (IllegalArgumentException | IllegalAccessException e) {
            throw new ELException(e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            Util.handleThrowable(cause);
            throw new ELException(cause);
        }

        context.setPropertyResolved(base, method);
        return result;
    }

    @Override
    public boolean isReadOnly(ELContext context, Object base, Object property) {
        Objects.requireNonNull(context);
        if (base == null || property == null) {
            return false;
        }

        context.setPropertyResolved(base, property);
        return this.readOnly || this.property(context, base, property).isReadOnly(base);
    }

    @Override
    public Iterator<FeatureDescriptor> getFeatureDescriptors(ELContext context, Object base) {
        if (base == null) {
            return null;
        }

        try {
            BeanInfo info = Introspector.getBeanInfo(base.getClass());
            PropertyDescriptor[] pds = info.getPropertyDescriptors();
            for (int i = 0; i < pds.length; i++) {
                pds[i].setValue(RESOLVABLE_AT_DESIGN_TIME, Boolean.TRUE);
                pds[i].setValue(TYPE, pds[i].getPropertyType());
            }
            return Arrays.asList((FeatureDescriptor[]) pds).iterator();
        } catch (IntrospectionException e) {
            //
        }

        return null;
    }

    @Override
    public Class<?> getCommonPropertyType(ELContext context, Object base) {
        if (base != null) {
            return Object.class;
        }

        return null;
    }
}
